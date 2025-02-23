#!/usr/bin/env python3
import argparse
import asyncio
import logging
import multiprocessing
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import traceback
import urllib.parse
import zipfile

import discord
from discord.ext import commands

import urllib3
import bs4
import dulwich.index
import dulwich.objects
import dulwich.pack
import requests
import socks
from requests_pkcs12 import Pkcs12Adapter


logger = logging.getLogger("gitdumpdiscord")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def join_url(base, path):
    """Safely join a base URL with a relative path."""
    if not base.endswith("/"):
        base += "/"
    return urllib.parse.urljoin(base, path)

def is_html(response):
    """Return True if the response is an HTML webpage."""
    return ("Content-Type" in response.headers and
            "text/html" in response.headers["Content-Type"])

def is_safe_path(path):
    """Prevent directory traversal attacks."""
    if os.path.isabs(path):
        return False
    safe_path = os.path.expanduser("~")
    try:
        full_path = os.path.realpath(os.path.join(safe_path, path))
    except Exception:
        return False
    return os.path.commonpath((full_path, safe_path)) == safe_path

def get_indexed_files(response):
    """Return all file paths listed in a directory index HTML page."""
    html = bs4.BeautifulSoup(response.text, "html.parser")
    files = []
    for link in html.find_all("a"):
        href = link.get("href")
        if not href:
            continue
        url = urllib.parse.urlparse(href)
        if url.path and is_safe_path(url.path) and not url.scheme and not url.netloc:
            files.append(url.path)
    return files

def verify_response(response):
    if response.status_code != 200:
        return (False,
                "[-] {} responded with status code {}\n".format(response.request.url, response.status_code))
    elif ("Content-Length" in response.headers and int(response.headers["Content-Length"]) == 0):
        return False, "[-] {} responded with a zero-length body\n".format(response.request.url)
    elif ("Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]):
        return False, "[-] {} responded with HTML\n".format(response.request.url)
    else:
        return True, True

def create_intermediate_dirs(path):
    """Create intermediate directories if they do not exist."""
    dirname = os.path.dirname(path)
    if dirname and not os.path.exists(dirname):
        try:
            os.makedirs(dirname)
        except FileExistsError:
            pass  # race condition

def get_referenced_sha1(obj_file):
    """Return all referenced SHA1 hashes in the given git object."""
    objs = []
    if isinstance(obj_file, dulwich.objects.Commit):
        objs.append(obj_file.tree.decode())
        for parent in obj_file.parents:
            objs.append(parent.decode())
    elif isinstance(obj_file, dulwich.objects.Tree):
        for item in obj_file.iteritems():
            objs.append(item.sha.decode())
    elif isinstance(obj_file, dulwich.objects.Blob):
        pass
    elif isinstance(obj_file, dulwich.objects.Tag):
        pass
    else:
        logger.error("Unexpected object type: %r", obj_file)
        return []
    return objs

# Worker classes for multiprocessing tasks.
class Worker(multiprocessing.Process):
    def __init__(self, pending_tasks, tasks_done, args):
        super().__init__()
        self.daemon = True
        self.pending_tasks = pending_tasks
        self.tasks_done = tasks_done
        self.args = args

    def run(self):
        self.init(*self.args)
        while True:
            task = self.pending_tasks.get(block=True)
            if task is None:
                return
            try:
                result = self.do_task(task, *self.args)
            except Exception:
                logger.exception("Task %s raised exception", task)
                result = []
            if not isinstance(result, list):
                logger.error("do_task() should return a list")
                result = []
            self.tasks_done.put(result)

    def init(self, *args):
        raise NotImplementedError

    def do_task(self, task, *args):
        raise NotImplementedError

def process_tasks(initial_tasks, worker, jobs, args=(), tasks_done_set=None):
    if not initial_tasks:
        return
    tasks_seen = set(tasks_done_set) if tasks_done_set else set()
    pending_tasks = multiprocessing.Queue()
    tasks_done = multiprocessing.Queue()
    num_pending_tasks = 0
    for task in initial_tasks:
        if task not in tasks_seen:
            pending_tasks.put(task)
            num_pending_tasks += 1
            tasks_seen.add(task)
    processes = [worker(pending_tasks, tasks_done, args) for _ in range(jobs)]
    for p in processes:
        p.start()
    while num_pending_tasks > 0:
        task_result = tasks_done.get(block=True)
        num_pending_tasks -= 1
        for task in task_result:
            if task not in tasks_seen:
                pending_tasks.put(task)
                num_pending_tasks += 1
                tasks_seen.add(task)
    for _ in range(jobs):
        pending_tasks.put(None)
    for p in processes:
        p.join()

class DownloadWorker(Worker):
    def init(self, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = http_headers
        if client_cert_p12:
            self.session.mount(url, Pkcs12Adapter(pkcs12_filename=client_cert_p12,
                                                   pkcs12_password=client_cert_p12_password))
        else:
            self.session.mount(url, requests.adapters.HTTPAdapter(max_retries=retry))

    def do_task(self, filepath, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None):
        local_path = os.path.join(directory, filepath)
        if os.path.isfile(local_path):
            logger.info("[-] Already downloaded %s", join_url(url, filepath))
            return []
        full_url = join_url(url, filepath)
        try:
            with self.session.get(full_url, allow_redirects=False, stream=True, timeout=timeout) as response:
                logger.info("[-] Fetching %s [%d]", full_url, response.status_code)
                valid, error_message = verify_response(response)
                if not valid:
                    logger.error(error_message)
                    return []
                abs_path = os.path.abspath(local_path)
                create_intermediate_dirs(abs_path)
                with open(abs_path, "wb") as f:
                    for chunk in response.iter_content(4096):
                        f.write(chunk)
        except Exception:
            logger.exception("Error fetching %s", full_url)
        return []

class RecursiveDownloadWorker(DownloadWorker):
    def do_task(self, filepath, url, directory, retry, timeout, http_headers):
        local_path = os.path.join(directory, filepath)
        if os.path.isfile(local_path):
            logger.info("[-] Already downloaded %s", join_url(url, filepath))
            return []
        full_url = join_url(url, filepath)
        try:
            with self.session.get(full_url, allow_redirects=False, stream=True, timeout=timeout) as response:
                logger.info("[-] Fetching %s [%d]", full_url, response.status_code)
                if (response.status_code in (301, 302) and "Location" in response.headers and 
                    response.headers["Location"].endswith(filepath + "/")):
                    return [filepath + "/"]
                if filepath.endswith("/"):
                    if not is_html(response):
                        logger.error("[-] %s did not return a valid HTML directory listing", full_url)
                        return []
                    return [filepath + filename for filename in get_indexed_files(response)]
                else:
                    valid, error_message = verify_response(response)
                    if not valid:
                        logger.error(error_message)
                        return []
                    abs_path = os.path.abspath(local_path)
                    create_intermediate_dirs(abs_path)
                    with open(abs_path, "wb") as f:
                        for chunk in response.iter_content(4096):
                            f.write(chunk)
        except Exception:
            logger.exception("Error fetching %s", full_url)
        return []

class FindRefsWorker(DownloadWorker):
    def do_task(self, filepath, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None):
        full_url = join_url(url, filepath)
        try:
            response = self.session.get(full_url, allow_redirects=False, timeout=timeout)
            logger.info("[-] Fetching %s [%d]", full_url, response.status_code)
            valid, error_message = verify_response(response)
            if not valid:
                logger.error(error_message)
                return []
            abs_path = os.path.abspath(os.path.join(directory, filepath))
            create_intermediate_dirs(abs_path)
            with open(abs_path, "w") as f:
                f.write(response.text)
            tasks = []
            for ref in re.findall(r"(refs(/[a-zA-Z0-9\-\.\_\*]+)+)", response.text):
                ref_str = ref[0]
                if not ref_str.endswith("*") and is_safe_path(ref_str):
                    tasks.append(".git/" + ref_str)
                    tasks.append(".git/logs/" + ref_str)
            return tasks
        except Exception:
            logger.exception("Error processing refs from %s", full_url)
            return []

class FindObjectsWorker(DownloadWorker):
    def do_task(self, obj, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None):
        filepath = ".git/objects/{}/{}".format(obj[:2], obj[2:])
        local_path = os.path.join(directory, filepath)
        full_url = join_url(url, filepath)
        if os.path.isfile(local_path):
            logger.info("[-] Already downloaded %s", full_url)
        else:
            try:
                response = self.session.get(full_url, allow_redirects=False, timeout=timeout)
                logger.info("[-] Fetching %s [%d]", full_url, response.status_code)
                valid, error_message = verify_response(response)
                if not valid:
                    logger.error(error_message)
                    return []
                abs_path = os.path.abspath(local_path)
                create_intermediate_dirs(abs_path)
                with open(abs_path, "wb") as f:
                    f.write(response.content)
            except Exception:
                logger.exception("Error fetching %s", full_url)
                return []
        try:
            obj_file = dulwich.objects.ShaFile.from_path(os.path.abspath(local_path))
            return get_referenced_sha1(obj_file)
        except Exception:
            logger.exception("Error parsing object file %s", local_path)
            return []

def sanitize_file(filepath):
    """In-place comment out possibly unsafe lines based on regex."""
    if not os.path.isfile(filepath):
        logger.error("File %s does not exist", filepath)
        return
    UNSAFE = r"^\s*fsmonitor|sshcommand|askpass|editor|pager"
    try:
        with open(filepath, 'r+') as f:
            content = f.read()
            modified_content = re.sub(UNSAFE, r'# \g<0>', content, flags=re.IGNORECASE)
            if content != modified_content:
                logger.warning("Warning: '%s' file was altered", filepath)
                f.seek(0)
                f.write(modified_content)
                f.truncate()
    except Exception:
        logger.exception("Error sanitizing file %s", filepath)

def fetch_git(url, directory, jobs, retry, timeout, http_headers,
              client_cert_p12=None, client_cert_p12_password=None):
    """
    Dump a git repository from the given website into the output directory.
    Instead of changing the working directory globally, we pass the output directory
    to subprocess calls.
    """
    if not os.path.isdir(directory):
        logger.error("Destination %s is not a directory", directory)
        return 1

    session = requests.Session()
    session.verify = False
    session.headers = http_headers
    if client_cert_p12:
        session.mount(url, Pkcs12Adapter(pkcs12_filename=client_cert_p12,
                                           pkcs12_password=client_cert_p12_password))
    else:
        session.mount(url, requests.adapters.HTTPAdapter(max_retries=retry))

    if os.listdir(directory):
        logger.warning("Warning: Destination '%s' is not empty", directory)

    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    url = url.rstrip("/")

    head_url = join_url(url, ".git/HEAD")
    logger.info("[-] Testing %s", head_url)
    try:
        response = session.get(head_url, timeout=timeout, allow_redirects=False)
    except Exception:
        logger.exception("Error accessing %s", head_url)
        return 1
    logger.info("[%d]", response.status_code)
    valid, error_message = verify_response(response)
    if not valid:
        logger.error(error_message)
        return 1
    elif not re.match(r"^(ref:.*|[0-9a-f]{40}$)", response.text.strip()):
        logger.error("error: %s/.git/HEAD is not a valid git HEAD file", url)
        return 1

    environment = os.environ.copy()
    configured_proxy = socks.getdefaultproxy()
    if configured_proxy is not None:
        proxy_types = ["http", "socks4h", "socks5h"]
        environment["ALL_PROXY"] = "http.proxy={}:{}:{}".format(
            proxy_types[configured_proxy[0]], configured_proxy[1], configured_proxy[2]
        )

    gitdir = join_url(url, ".git/")
    logger.info("[-] Testing %s", gitdir)
    try:
        response = session.get(gitdir, allow_redirects=False)
    except Exception:
        logger.exception("Error accessing %s", gitdir)
        return 1
    logger.info("[%d]", response.status_code)

    if (response.status_code == 200 and is_html(response) and "HEAD" in get_indexed_files(response)):
        logger.info("[-] Fetching .git recursively")
        process_tasks(
            [".git/", ".gitignore"],
            RecursiveDownloadWorker,
            jobs,
            args=(url, directory, retry, timeout, http_headers),
        )
        logger.info("[-] Sanitizing .git/config")
        sanitize_file(os.path.join(directory, ".git", "config"))
        try:
            logger.info("[-] Running git checkout .")
            subprocess.check_call(["git", "checkout", "."], cwd=directory, env=environment)
        except subprocess.CalledProcessError:
            logger.error("git checkout failed")
        return 0

    # No directory listing – fetch common files.
    logger.info("[-] Fetching common files")
    tasks = [
        ".gitignore",
        ".git/COMMIT_EDITMSG",
        ".git/description",
        ".git/hooks/applypatch-msg.sample",
        ".git/hooks/commit-msg.sample",
        ".git/hooks/post-commit.sample",
        ".git/hooks/post-receive.sample",
        ".git/hooks/post-update.sample",
        ".git/hooks/pre-applypatch.sample",
        ".git/hooks/pre-commit.sample",
        ".git/hooks/pre-push.sample",
        ".git/hooks/pre-rebase.sample",
        ".git/hooks/pre-receive.sample",
        ".git/hooks/prepare-commit-msg.sample",
        ".git/hooks/update.sample",
        ".git/index",
        ".git/info/exclude",
        ".git/objects/info/packs",
    ]
    process_tasks(
        tasks,
        DownloadWorker,
        jobs,
        args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password),
    )

    # Find refs.
    logger.info("[-] Finding refs/")
    tasks = [
        ".git/FETCH_HEAD",
        ".git/HEAD",
        ".git/ORIG_HEAD",
        ".git/config",
        ".git/info/refs",
        ".git/logs/HEAD",
        ".git/logs/refs/heads/main",
        ".git/logs/refs/heads/master",
        ".git/logs/refs/heads/staging",
        ".git/logs/refs/heads/production",
        ".git/logs/refs/heads/development",
        ".git/logs/refs/remotes/origin/HEAD",
        ".git/logs/refs/remotes/origin/main",
        ".git/logs/refs/remotes/origin/master",
        ".git/logs/refs/remotes/origin/staging",
        ".git/logs/refs/remotes/origin/production",
        ".git/logs/refs/remotes/origin/development",
        ".git/logs/refs/stash",
        ".git/packed-refs",
        ".git/refs/heads/main",
        ".git/refs/heads/master",
        ".git/refs/heads/staging",
        ".git/refs/heads/production",
        ".git/refs/heads/development",
        ".git/refs/remotes/origin/HEAD",
        ".git/refs/remotes/origin/main",
        ".git/refs/remotes/origin/master",
        ".git/refs/remotes/origin/staging",
        ".git/refs/remotes/origin/production",
        ".git/refs/remotes/origin/development",
        ".git/refs/stash",
        ".git/refs/wip/wtree/refs/heads/main",
        ".git/refs/wip/wtree/refs/heads/master",
        ".git/refs/wip/wtree/refs/heads/staging",
        ".git/refs/wip/wtree/refs/heads/production",
        ".git/refs/wip/wtree/refs/heads/development",
        ".git/refs/wip/index/refs/heads/main",
        ".git/refs/wip/index/refs/heads/master",
        ".git/refs/wip/index/refs/heads/staging",
        ".git/refs/wip/index/refs/heads/production",
        ".git/refs/wip/index/refs/heads/development"
    ]
    process_tasks(
        tasks,
        FindRefsWorker,
        jobs,
        args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password),
    )

    logger.info("[-] Finding packs")
    tasks = []
    info_packs_path = os.path.join(directory, ".git", "objects", "info", "packs")
    if os.path.exists(info_packs_path):
        try:
            with open(info_packs_path, "r") as f:
                info_packs = f.read()
            for sha1 in re.findall(r"pack-([a-f0-9]{40})\.pack", info_packs):
                tasks.append(".git/objects/pack/pack-{}.idx".format(sha1))
                tasks.append(".git/objects/pack/pack-{}.pack".format(sha1))
        except Exception:
            logger.exception("Error processing %s", info_packs_path)
    process_tasks(
        tasks,
        DownloadWorker,
        jobs,
        args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password),
    )

    # Find objects.
    logger.info("[-] Finding objects")
    objs = set()
    packed_objs = set()
    files = [
        os.path.join(directory, ".git", "packed-refs"),
        os.path.join(directory, ".git", "info", "refs"),
        os.path.join(directory, ".git", "FETCH_HEAD"),
        os.path.join(directory, ".git", "ORIG_HEAD"),
    ]
    for dirpath, _, filenames in os.walk(os.path.join(directory, ".git", "refs")):
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))
    for dirpath, _, filenames in os.walk(os.path.join(directory, ".git", "logs")):
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))
    for filepath in files:
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath, "r") as f:
                content = f.read()
            for obj in re.findall(r"(^|\s)([a-f0-9]{40})($|\s)", content):
                objs.add(obj[1])
        except Exception:
            logger.exception("Error reading %s", filepath)
    index_path = os.path.join(directory, ".git", "index")
    if os.path.exists(index_path):
        try:
            index = dulwich.index.Index(index_path)
            for entry in index.iterobjects():
                objs.add(entry[1].decode())
        except Exception:
            logger.exception("Error reading index %s", index_path)
    pack_file_dir = os.path.join(directory, ".git", "objects", "pack")
    if os.path.isdir(pack_file_dir):
        for filename in os.listdir(pack_file_dir):
            if filename.startswith("pack-") and filename.endswith(".pack"):
                pack_data_path = os.path.join(pack_file_dir, filename)
                pack_idx_path = os.path.join(pack_file_dir, filename[:-5] + ".idx")
                try:
                    pack_data = dulwich.pack.PackData(pack_data_path)
                    pack_idx = dulwich.pack.load_pack_index(pack_idx_path)
                    pack = dulwich.pack.Pack.from_objects(pack_data, pack_idx)
                    for obj_file in pack.iterobjects():
                        packed_objs.add(obj_file.sha().hexdigest())
                        objs |= set(get_referenced_sha1(obj_file))
                except Exception:
                    logger.exception("Error processing pack file %s", filename)
    logger.info("[-] Fetching objects")
    process_tasks(
        objs,
        FindObjectsWorker,
        jobs,
        args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password),
        tasks_done_set=packed_objs,
    )
    logger.info("[-] Running git checkout .")
    sanitize_file(os.path.join(directory, ".git", "config"))
    try:
        subprocess.call(["git", "checkout", "."], cwd=directory,
                        stderr=open(os.devnull, "wb"), env=environment)
    except Exception:
        logger.exception("Error running git checkout")
    return 0


intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

@bot.tree.command(name="gitdump", description="dump a git repository given a url, assuming said platform has it.")
async def gitdump(
    interaction: discord.Interaction,
    url: str,
    jobs: int = 10,
    retry: int = 3,
    timeout: int = 3,
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
    header: str = None,
    proxy: str = None,
    client_cert_p12: str = None,
    client_cert_p12_password: str = None
):
    embed = discord.Embed(title="dumping .git...", description="please wait while the repository is being dumped.", color=0x00FF00)
    await interaction.response.send_message(embed=embed, ephemeral=False)

    http_headers = {"User-Agent": user_agent}
    if header:
        try:
            name, value = header.split("=", 1)
            http_headers[name.strip()] = value.strip()
        except Exception:
            pass

    if proxy:
        proxy_valid = False
        for pattern, proxy_type in [
            (r"^socks5:(.*):(\d+)$", socks.PROXY_TYPE_SOCKS5),
            (r"^socks4:(.*):(\d+)$", socks.PROXY_TYPE_SOCKS4),
            (r"^http://(.*):(\d+)$", socks.PROXY_TYPE_HTTP),
            (r"^(.*):(\d+)$", socks.PROXY_TYPE_SOCKS5),
        ]:
            m = re.match(pattern, proxy)
            if m:
                socks.setdefaultproxy(proxy_type, m.group(1), int(m.group(2)))
                socket.socket = socks.socksocket
                proxy_valid = True
                logger.debug("Proxy set to %s", proxy)
                break
        if not proxy_valid:
            await interaction.followup.send("proxies a bit cooked")
            return

    if url.rstrip("/").endswith(".git"):
        url = url.rstrip("/")[:-4]
    url = url.rstrip("/")

    tempdir = tempfile.mkdtemp(prefix="gitdump_")
    logger.info("dumping into temporary directory: %s", tempdir)

    try:
        result = await asyncio.to_thread(fetch_git, url, tempdir, jobs, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password)
    except Exception as e:
        logger.exception("Error during git dump")
        await interaction.followup.send("error occurred mid-dump.")
        shutil.rmtree(tempdir)
        return

    if result != 0:
        await interaction.followup.send("error dumping the repository.")
        shutil.rmtree(tempdir)
        return

    zippath = tempdir + ".zip"
    try:
        with zipfile.ZipFile(zippath, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(tempdir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=tempdir)
                    zipf.write(file_path, arcname)
    except Exception:
        logger.exception("error zipping the dump")
        await interaction.followup.send("error creating zip file.")
        shutil.rmtree(tempdir)
        return

    try:
        await interaction.followup.send(content="dump complete", file=discord.File(zippath, filename="out.zip"))
    except Exception:
        logger.exception("error sending zip file")
        await interaction.followup.send("error sending zip file.")
    finally:
        shutil.rmtree(tempdir)
        os.remove(zippath)

if __name__ == "__main__":
    TOKEN = os.getenv("DISCORD_BOT_TOKEN")
    if not TOKEN:
        logger.error("errrm wtf.")
        sys.exit(1)
    async def main():
        await bot.wait_until_ready()
        try:
            synced = await bot.tree.sync()
            logger.info("Synced %d commands", len(synced))
        except Exception:
            logger.exception("err syncing commands")
    bot.loop.create_task(main())
    bot.run(TOKEN)
