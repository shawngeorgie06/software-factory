#!/usr/bin/env python3
"""Single-task Linux VM runner. Only the Python standard library is required.

The host must dedicate factory-agent's UID to this one task. All failures exposed
outside this process are fixed phase labels; child output is never logged.
"""
import argparse
import datetime as dt
import fcntl
import json
import multiprocessing
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
import uuid

PATH = '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
LIMIT = 2 * 1024 * 1024
FILE_LIMIT = 16 * 1024 * 1024
TREE_LIMIT = 256 * 1024 * 1024
FILE_COUNT = 100000
LOCK_WAIT = 45
WORK_ROOT = '/var/lib/software-factory'


class Failure(Exception):
    pass


class HTTPFailure(Failure):
    def __init__(self, retryable=False):
        super().__init__('http')
        self.retryable = retryable


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Failure('http')


def timestamp(value):
    if not isinstance(value, str):
        raise Failure('credentials')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.timestamp()
    except (ValueError, OverflowError):
        raise Failure('credentials') from None


def repository(value):
    if not isinstance(value, str):
        raise Failure('assignment')
    match = re.fullmatch(r'https://github\.com/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,104})', value)
    if not match:
        raise Failure('assignment')
    owner, name = match.groups()
    if name.endswith('.git'):
        name = name[:-4]
    if not name or len(name) > 100 or name in ('.', '..') or owner in ('.', '..'):
        raise Failure('assignment')
    return owner, name, f'https://github.com/{owner}/{name}.git'


def assignment(value):
    if not isinstance(value, dict):
        raise Failure('assignment')
    repository(value.get('repo_url'))
    instructions, command = value.get('instructions'), value.get('check_command')
    if not isinstance(instructions, str) or not instructions.strip() or len(instructions.encode()) > 65536 or '\0' in instructions:
        raise Failure('assignment')
    if (not isinstance(command, list) or not 1 <= len(command) <= 64
            or not command[0]
            or any(not isinstance(x, str) or '\0' in x or len(x.encode()) > 4096 for x in command)
            or sum(len(x.encode()) for x in command) > 16384):
        raise Failure('assignment')
    return value


def clean_env(home):
    return {'PATH': PATH, 'HOME': str(home), 'LANG': 'C.UTF-8',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_TERMINAL_PROMPT': '0', 'GIT_ATTR_NOSYSTEM': '1'}


class Processes:
    """Bound elapsed time, captured output, process groups, and inherited state."""
    def run(self, argv, *, env, cwd=None, data=None, capture=False,
            timeout=300, guard=lambda: None, accepted=(0,), sink=None):
        guard()
        # A private regular file avoids deadlocking on an unconsumed prompt pipe.
        with tempfile.TemporaryFile() as stdin:
            if data is not None:
                stdin.write(data)
            stdin.seek(0)
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdin,
                                       stdout=subprocess.PIPE if capture or sink else subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
            output = bytearray()
            selector = selectors.DefaultSelector()
            if capture or sink:
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
            end = time.monotonic() + timeout
            try:
                while True:
                    guard()
                    if time.monotonic() >= end:
                        raise Failure('process')
                    if capture or sink:
                        for key, _ in selector.select(0.05):
                            chunk = os.read(key.fd, 65536)
                            if chunk:
                                if sink:
                                    sink(chunk)
                                else:
                                    output.extend(chunk)
                                if len(output) > LIMIT:
                                    raise Failure('process')
                            else:
                                selector.unregister(key.fileobj)
                    else:
                        time.sleep(0.05)
                    if process.poll() is not None and (not (capture or sink) or not selector.get_map()):
                        break
                if process.returncode not in accepted:
                    raise Failure('process')
                guard()
                return bytes(output)
            finally:
                selector.close()
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                if process.stdout:
                    process.stdout.close()


class HTTP:
    def __init__(self):
        # Ignore proxy environment and never forward authorization on redirects.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, url, token, body=None, timeout=10):
        # Socket timeouts alone permit an endless slow-drip response. An isolated
        # transport process gives headers, body, and DNS one total time budget.
        context = multiprocessing.get_context('spawn')
        receiver, sender = context.Pipe(duplex=False)
        child = context.Process(target=_http_worker, args=(sender, method, url, token, body, timeout))
        try:
            child.start()
            sender.close()
            if not receiver.poll(timeout):
                raise HTTPFailure(True)
            ok, value = receiver.recv()
            if not ok:
                raise HTTPFailure(value is True)
            return value
        except HTTPFailure:
            raise
        except Exception:
            raise HTTPFailure(True) from None
        finally:
            receiver.close()
            sender.close()
            if child.pid is not None:
                if child.is_alive():
                    child.kill()
                child.join(timeout=2)

    def _request(self, method, url, token, body=None, timeout=10):
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json',
                   'User-Agent': 'software-factory-vm'}
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=timeout) as response:
                raw = response.read(LIMIT + 1)
                if not 200 <= response.status < 300:
                    raise HTTPFailure(500 <= response.status <= 599)
                if len(raw) > LIMIT:
                    raise Failure('http')
                return json.loads(raw) if raw else None
        except HTTPFailure:
            raise
        except urllib.error.HTTPError as error:
            raise HTTPFailure(500 <= error.code <= 599) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise HTTPFailure(True) from None
        except Exception:
            raise HTTPFailure() from None


def _http_worker(connection, method, url, token, body, timeout):
    try:
        connection.send((True, HTTP()._request(method, url, token, body, timeout)))
    except HTTPFailure as error:
        connection.send((False, error.retryable))
    except Exception:
        connection.send((False, False))
    finally:
        connection.close()


class Lease:
    def __init__(self, callback, deadline, now=time.time, interval=15):
        self.callback, self.deadline, self.now = callback, deadline, now
        self.interval = interval
        self.stopped = threading.Event()
        self.rejected = threading.Event()
        self.last = now()
        self.thread = None

    def guard(self):
        if self.rejected.is_set() or self.now() >= self.deadline or self.now() - self.last > 30:
            raise Failure('lease')

    def beat(self):
        self.guard()
        try:
            self.callback()
            self.last = self.now()
        except Exception:
            self.rejected.set()
            raise Failure('lease') from None
        self.guard()

    def start(self):
        self.beat()  # Admission gate: no repository work may precede this.
        def loop():
            while not self.stopped.wait(self.interval):
                try:
                    self.beat()
                except Exception:
                    self.rejected.set()
                    return
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def close(self):
        self.stopped.set()
        if self.thread:
            self.thread.join(timeout=15)
            if self.thread.is_alive():
                self.rejected.set()


class StagedEntries:
    """Bound the index by entries and path size rather than a 2 MiB capture."""
    def __init__(self, guard):
        self.guard, self.pending, self.oids, self.count = guard, b'', {}, 0

    def feed(self, chunk):
        parts = (self.pending + chunk).split(b'\0')
        self.pending = parts.pop()
        if len(self.pending) > 8192:
            raise Failure('snapshot')
        for entry in parts:
            self.guard()
            if len(entry) > 8192 or b'\t' not in entry:
                raise Failure('snapshot')
            metadata, path = entry.split(b'\t', 1)
            fields = metadata.split()
            if (len(fields) != 3 or fields[0] not in (b'100644', b'100755') or fields[2] != b'0'
                    or not re.fullmatch(b'[0-9a-f]{40}|[0-9a-f]{64}', fields[1]) or not path):
                raise Failure('snapshot')
            self.count += 1
            if self.count > FILE_COUNT:
                raise Failure('snapshot')
            self.oids[fields[1]] = self.oids.get(fields[1], 0) + 1

    def finish(self):
        if self.pending:
            raise Failure('snapshot')


class StagedBlobs:
    """Scan exact indexed blobs through one bounded cat-file batch process."""
    def __init__(self, oids, secrets, guard):
        self.entries = list(oids.items())
        self.secrets, self.guard = secrets, guard
        self.overlap = max(map(len, secrets)) - 1
        self.index = self.total = 0
        self.remaining = None
        self.header = self.tail = b''

    def feed(self, chunk):
        while chunk:
            self.guard()
            if self.remaining is None:
                head, separator, chunk = chunk.partition(b'\n')
                self.header += head
                if len(self.header) > 128:
                    raise Failure('snapshot')
                if not separator:
                    return
                fields = self.header.split()
                if (self.index >= len(self.entries) or len(fields) != 3 or fields[1] != b'blob'
                        or fields[0] != self.entries[self.index][0] or not fields[2].isdigit()):
                    raise Failure('snapshot')
                self.remaining = int(fields[2])
                self.total += self.remaining * self.entries[self.index][1]
                if self.remaining > FILE_LIMIT or self.total > TREE_LIMIT:
                    raise Failure('snapshot')
                self.header = self.tail = b''
            elif self.remaining:
                take = min(self.remaining, len(chunk))
                data = self.tail + chunk[:take]
                if any(secret in data for secret in self.secrets):
                    raise Failure('snapshot')
                self.tail = data[-self.overlap:] if self.overlap else b''
                self.remaining -= take
                chunk = chunk[take:]
            else:
                if chunk[:1] != b'\n':
                    raise Failure('snapshot')
                chunk = chunk[1:]
                self.index += 1
                self.remaining = None

    def finish(self):
        if self.remaining is not None or self.header or self.index != len(self.entries):
            raise Failure('snapshot')


class Runner:
    def __init__(self, args, processes=None, http=None, now=time.time):
        self.args = args
        self.processes, self.http, self.now = processes or Processes(), http or HTTP(), now
        self.lease = None
        self.secret = None
        self.phase = 'initialization'
        self.private = None
        self.work = None
        self.account = None
        self.uid_owned = False
        self.host_lock = None

    def guard(self):
        if self.lease:
            self.lease.guard()

    def run_process(self, argv, *, capture=False, cwd=None, data=None, env=None, timeout=300, sink=None):
        self.guard()
        if self.lease:
            timeout = min(timeout, max(0.01, self.lease.deadline - self.now()))
        return self.processes.run(argv, capture=capture, cwd=cwd, data=data,
                                  env=env or clean_env(self.private or '/'), timeout=timeout, guard=self.guard, sink=sink)

    def request(self, method, url, token, body=None, retry=False):
        for attempt in range(3 if retry else 1):
            self.guard()
            timeout = min(10, max(0.01, self.lease.deadline - self.now())) if self.lease else 10
            try:
                result = self.http.request(method, url, token, body, timeout=timeout)
                self.guard()
                return result
            except HTTPFailure as error:
                if not error.retryable or not retry or attempt == 2:
                    raise
            end = time.monotonic() + 0.25 * (attempt + 1)
            while time.monotonic() < end:
                self.guard()
                time.sleep(0.05)

    def callback(self, endpoint, body=None, method='POST', retry=None):
        if retry is None:
            retry = endpoint in ('assignment', 'verifying', 'result')
        return self.request(method, self.task_url + '/' + endpoint, self.secret['callback_token'], body, retry=retry)

    def load_secret(self):
        raw = self.run_process(['aws', 'ssm', 'get-parameter', '--name', self.args.parameter,
                                '--region', self.args.region, '--with-decryption', '--query',
                                'Parameter.Value', '--output', 'text'], capture=True, timeout=30)
        try:
            secret = json.loads(raw)
            if not isinstance(secret, dict):
                raise ValueError()
            for key in ('github_token', 'model_api_key'):
                if not isinstance(secret[key], str) or not 1 <= len(secret[key]) <= 16384 or any(c in secret[key] for c in '\r\n\0'):
                    raise ValueError()
            if not isinstance(secret['callback_token'], str) or not re.fullmatch('[0-9a-fA-F]{64}', secret['callback_token']):
                raise ValueError()
            deadline = min(timestamp(secret['expires_at']), timestamp(secret['github_expires_at']) - 60)
            if deadline <= self.now():
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise Failure('credentials') from None
        self.secret = secret
        return deadline

    def validate_host(self):
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise Failure('host')
        self.acquire_host_lock()
        self.account = pwd.getpwnam('factory-agent')
        if self.account.pw_uid == 0 or self.account.pw_gid == 0:
            raise Failure('host')
        if self.account.pw_dir != '/home/factory-agent' or not Path(self.account.pw_dir).is_dir() or Path(self.account.pw_dir).is_symlink():
            raise Failure('host')
        storage = Path(WORK_ROOT).lstat()
        if not stat.S_ISDIR(storage.st_mode) or storage.st_uid != 0 or storage.st_mode & 0o022 or not storage.st_mode & 0o001:
            raise Failure('host')
        for tool in ('setpriv', 'unshare', 'mount', 'python3', 'pkill', 'git', 'codex', 'aws', 'iptables', 'ip6tables'):
            if not shutil.which(tool, path=PATH):
                raise Failure('host')
        self.verify_metadata_firewall()

    def acquire_host_lock(self):
        self.host_lock = os.open('/run/factory-runner.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        end = time.monotonic() + LOCK_WAIT
        while True:
            try:
                fcntl.flock(self.host_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= end:
                    raise Failure('host') from None
                time.sleep(0.1)

    def verify_metadata_firewall(self):
        # Require the first OUTPUT rule, so an earlier ACCEPT/jump cannot bypass it.
        for tool, address, reject in (('iptables', '169.254.169.254/32', 'icmp-port-unreachable'),
                                      ('ip6tables', 'fd00:ec2::254/128', 'icmp6-port-unreachable')):
            rules = self.run_process([tool, '-w', '5', '-S', 'OUTPUT'], capture=True).decode().splitlines()
            effective = [line.split() for line in rules if line.startswith('-A ')]
            expected = ['-A', 'OUTPUT', '-d', address, '-m', 'owner', '--uid-owner',
                        str(self.account.pw_uid), '-j', 'REJECT', '--reject-with', reject]
            if not effective or effective[0] != expected:
                raise Failure('host')
        probe = """import errno, socket
for family, address in ((socket.AF_INET, '169.254.169.254'), (socket.AF_INET6, 'fd00:ec2::254')):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((address, 80))
        if result not in (errno.ECONNREFUSED, errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH):
            raise SystemExit(1)
"""
        self.run_process(self.drop_privileges() + ['--', 'python3', '-I', '-c', probe], timeout=5)

    def drop_privileges(self):
        return ['setpriv', '--reuid', str(self.account.pw_uid), '--regid', str(self.account.pw_gid),
                '--clear-groups', '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all']

    def prepare(self):
        self.uid_owned = True
        self.kill_agent()
        self.private = Path(tempfile.mkdtemp(prefix='factory-private-', dir=WORK_ROOT))
        os.chmod(self.private, 0o700)
        self.work = Path(tempfile.mkdtemp(prefix='factory-agent-', dir=WORK_ROOT))
        # Root owns the container so the UID cannot replace an ancestor with a symlink.
        os.chmod(self.work, 0o711)
        # These files and the trusted repository remain root-only throughout.
        token = self.private / 'github-token'
        token.write_text(self.secret['github_token'])
        token.chmod(0o600)
        askpass = self.private / 'askpass'
        askpass.write_text('#!/usr/bin/python3\nimport pathlib, sys\nprint("x-access-token" if "Username" in sys.argv[1] else pathlib.Path(__file__).with_name("github-token").read_text())\n')
        askpass.chmod(0o700)
        self.git_env = clean_env(self.private)
        self.git_env['GIT_ASKPASS'] = str(askpass)
        self.trusted = self.private / 'repository'
        self.source = self.work / 'source'

    def kill_agent(self):
        if self.account and self.uid_owned:
            end = time.monotonic() + 5
            while True:
                self.processes.run(['pkill', '-KILL', '-u', str(self.account.pw_uid)],
                                   env=clean_env('/'), timeout=5, accepted=(0, 1))
                live = False
                for entry in Path('/proc').iterdir():
                    if not entry.name.isdecimal():
                        continue
                    try:
                        status = (entry / 'status').read_text()
                        uid = re.search(r'^Uid:\s+(\d+)', status, re.M)
                        state = re.search(r'^State:\s+(\w)', status, re.M)
                        if uid and int(uid[1]) == self.account.pw_uid and state and state[1] != 'Z':
                            live = True
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                if not live:
                    return
                if time.monotonic() >= end:
                    raise Failure('process')
                time.sleep(0.05)

    def unprivileged(self, command, workspace, *, prompt=None, model=False, network=False):
        home = self.work / ('model-home' if model else 'check-home')
        home.mkdir(mode=0o700)
        os.chown(home, self.account.pw_uid, self.account.pw_gid)
        env = clean_env(home)
        if model:
            env.update(CODEX_HOME=str(home / '.codex'), CODEX_API_KEY=self.secret['model_api_key'])
        # Only this fixed launcher runs as root. Each invocation gets fresh tmpfs
        # mounts, and checks cannot inherit the model's scratch files or real home.
        targets = ['/tmp', '/var/tmp', '/dev/shm', self.account.pw_dir]
        model_home = self.work / 'model-home'
        if not model and model_home.exists():
            targets.append(str(model_home))
        setup = """import os, subprocess, sys
count = int(sys.argv[1])
for target in sys.argv[2:2+count]:
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'nosuid,nodev,mode=1777,size=512m', 'tmpfs', target], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.execvpe(sys.argv[2+count], sys.argv[2+count:], os.environ)
"""
        prefix = ['unshare', '--mount', '--propagation', 'private']
        if not network:
            prefix += ['--net']
        prefix += ['--', 'python3', '-I', '-c', setup, str(len(targets)), *targets, *self.drop_privileges()]
        try:
            self.run_process(prefix + ['--'] + command, cwd=workspace, env=env,
                             data=prompt.encode() if prompt is not None else None, timeout=3600)
        finally:
            self.kill_agent()

    def git(self, *args, capture=True, data=None, sink=None):
        return self.run_process(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                                 '-c', 'http.followRedirects=false', '-c', 'protocol.file.allow=never',
                                 '-c', 'protocol.ext.allow=never', '--git-dir=' + str(self.trusted / '.git'),
                                 '--work-tree=' + str(self.source), *args], capture=capture, env=self.git_env, data=data, sink=sink)

    def own_tree(self, root):
        os.chmod(root, 0o700)
        for base, dirs, files in os.walk(root):
            os.chown(base, self.account.pw_uid, self.account.pw_gid)
            for name in dirs + files:
                os.chown(Path(base) / name, self.account.pw_uid, self.account.pw_gid)

    def validate_tree(self, root):
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise Failure('snapshot')
        count = directories = total = 0
        for base, dirs, files in os.walk(root, followlinks=False):
            # Agent's own .git is deliberately ignored by root publishing.
            if Path(base) == root and '.git' in dirs:
                dirs.remove('.git')
            for name in dirs + files:
                self.guard()
                path = Path(base) / name
                info = path.lstat()
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                    raise Failure('snapshot')
                if name.casefold() == '.git' and path != root / '.git':
                    raise Failure('snapshot')
                if stat.S_ISREG(info.st_mode):
                    count += 1
                    total += info.st_size
                else:
                    directories += 1
                if count > FILE_COUNT or directories > FILE_COUNT or total > TREE_LIMIT or info.st_size > FILE_LIMIT:
                    raise Failure('snapshot')
        if (root / '.git').is_symlink():
            raise Failure('snapshot')

    def clone(self, url):
        self.run_process(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                          '-c', 'http.followRedirects=false', '-c', 'protocol.file.allow=never',
                          'clone', '--no-recurse-submodules', '--', url, str(self.trusted)], env=self.git_env, timeout=600)
        # HEAD is selected by the authenticated remote, not assignment/model text.
        default_ref = self.run_process(['git', '-c', 'core.hooksPath=/dev/null',
                                       '--git-dir=' + str(self.trusted / '.git'), 'symbolic-ref',
                                       'refs/remotes/origin/HEAD'], env=self.git_env, capture=True).decode().strip()
        if not default_ref.startswith('refs/remotes/origin/'):
            raise Failure('clone')
        self.base = default_ref.removeprefix('refs/remotes/origin/')
        self.initial = self.run_process(['git', '--git-dir=' + str(self.trusted / '.git'),
                                         'rev-parse', 'HEAD'], env=self.git_env, capture=True).decode().strip()
        self.validate_tree(self.trusted)
        shutil.copytree(self.trusted, self.source, ignore=shutil.ignore_patterns('.git'))
        self.own_tree(self.source)
        # Initialize an independent, unprivileged Git repository for Codex discovery.
        self.unprivileged(['git', '-c', 'core.hooksPath=/dev/null', 'init', '--quiet'], self.source, network=False)
        # unprivileged() allocates a per-invocation home.
        shutil.rmtree(self.work / 'check-home')

    def reject_project_config(self):
        self.validate_tree(self.source)
        for parent in self.source.parents:
            config = parent / '.codex'
            if config.exists() or config.is_symlink():
                raise Failure('agent')
        for base, dirs, files in os.walk(self.source):
            if Path(base) == self.source and '.git' in dirs:
                dirs.remove('.git')
            if any(name.casefold() == '.codex' for name in dirs + files):
                raise Failure('agent')

    def snapshot(self):
        self.kill_agent()
        self.validate_tree(self.source)
        self.git('add', '--all', '--', '.', capture=False)
        entries = StagedEntries(self.guard)
        self.git('ls-files', '--stage', '-z', capture=False, sink=entries.feed)
        entries.finish()
        blobs = StagedBlobs(entries.oids, [self.secret[key].encode() for key in
                                          ('callback_token', 'github_token', 'model_api_key')], self.guard)
        self.git('cat-file', '--batch', capture=False, data=b''.join(oid + b'\n' for oid in entries.oids), sink=blobs.feed)
        blobs.finish()
        self.tree = self.git('write-tree').decode().strip()
        original_tree = self.git('rev-parse', self.initial + '^{tree}').decode().strip()
        self.changed = self.tree != original_tree
        verify = self.work / 'verify'
        verify.mkdir(mode=0o700)
        self.git('checkout-index', '--all', '--prefix=' + str(verify) + '/', capture=False)
        self.own_tree(verify)
        return verify

    def publish(self, owner, name):
        branch = 'factory/task-' + self.args.task_id
        if not self.changed:
            return {'status': 'no_changes', 'branch': branch, 'commit': self.initial, 'pr_url': None}
        # Deterministic commit, including timestamps, makes retry collisions verifiable.
        env = dict(self.git_env, GIT_AUTHOR_NAME='Software Factory', GIT_AUTHOR_EMAIL='factory@localhost',
                   GIT_COMMITTER_NAME='Software Factory', GIT_COMMITTER_EMAIL='factory@localhost',
                   GIT_AUTHOR_DATE=self.commit_date, GIT_COMMITTER_DATE=self.commit_date)
        commit = self.run_process(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                                   '--git-dir=' + str(self.trusted / '.git'), 'commit-tree', self.tree,
                                   '-p', self.initial], data=('Factory task ' + self.args.task_id + '\n').encode(),
                                  env=env, capture=True).decode().strip()
        existing = self.git('ls-remote', '--heads', 'origin', 'refs/heads/' + branch).decode().strip()
        if existing and existing.split()[0] != commit:
            raise Failure('publish')
        if not existing:
            # Empty lease is a compare-and-create guard, never overwrites a branch.
            self.git('push', '--no-force', '--force-with-lease=refs/heads/' + branch + ':', 'origin',
                     commit + ':refs/heads/' + branch, capture=False)
        api = f'https://api.github.com/repos/{owner}/{name}/pulls'
        query = urllib.parse.urlencode({'head': owner + ':' + branch, 'base': self.base, 'state': 'all'})
        pulls = self.request('GET', api + '?' + query, self.secret['github_token'])
        if not isinstance(pulls, list):
            raise Failure('publish')
        if pulls:
            pr = pulls[0]
            if not isinstance(pr, dict) or pr.get('state') not in ('open', 'closed'):
                raise Failure('publish')
            status = 'pr_closed' if pr['state'] == 'closed' else 'pr_existing'
        else:
            status = 'pr_created'
            pr = self.request('POST', api, self.secret['github_token'],
                              {'head': branch, 'base': self.base, 'title': 'Factory task ' + self.args.task_id,
                               'body': 'Automated implementation. Configured verification completed successfully.'})
        url = pr.get('html_url') if isinstance(pr, dict) else None
        if not isinstance(url, str) or not re.fullmatch(re.escape(f'https://github.com/{owner}/{name}/pull/') + r'[1-9][0-9]*', url, flags=re.IGNORECASE | re.ASCII):
            raise Failure('publish')
        return {'status': status, 'branch': branch, 'commit': commit, 'pr_url': url}

    def execute(self):
        try:
            self.validate_host()
            deadline = self.load_secret()
            self.task_url = self.args.base_url.rstrip('/') + '/v1/tasks/' + self.args.task_id
            self.lease = Lease(lambda: self.callback('heartbeat', retry=self.lease.thread is None), deadline, self.now)
            self.lease.start()
            self.phase = 'assignment'
            task = assignment(self.callback('assignment', method='GET'))
            owner, name, url = repository(task['repo_url'])
            self.phase = 'host'
            self.prepare()
            self.phase = 'clone'
            self.clone(url)
            # The trusted base commit supplies a stable date across attempt retries.
            self.commit_date = self.git('show', '-s', '--format=%ct', self.initial).decode().strip()
            if not self.commit_date.isdecimal():
                raise Failure('clone')
            self.commit_date = '@' + self.commit_date + ' +0000'
            self.reject_project_config()
            self.phase = 'agent'
            self.unprivileged(['codex', 'exec', '--sandbox', 'workspace-write', '--ephemeral',
                               '--ignore-user-config', '--ignore-rules', '-c', 'approval_policy="never"', '-c',
                               'sandbox_workspace_write.network_access=false', '-m', self.args.model, '-'],
                              self.source, prompt=task['instructions'], model=True, network=True)
            self.phase = 'snapshot'
            verify = self.snapshot()
            self.phase = 'verification'
            self.callback('verifying')
            self.unprivileged(task['check_command'], verify, network=False)
            self.guard()
            self.phase = 'publish'
            result = self.publish(owner, name)
            self.phase = 'result'
            # A heartbeat racing a committed result would reject the now-terminal task
            # and incorrectly suppress an otherwise valid idempotent result retry.
            self.lease.close()
            self.callback('result', {'result': json.dumps(result, separators=(',', ':'))})
            return 0
        except Exception:
            try:
                self.kill_agent()
            except Exception:
                pass
            if self.secret and self.lease:
                try:
                    self.callback('failure', {'reason': 'runner ' + self.phase + ' failed'})
                except Exception:
                    pass
            print('runner failed', file=sys.stderr)
            return 1
        finally:
            handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
            if self.lease:
                self.lease.close()
            if self.work:
                # UID processes are dead before root removes potentially hostile paths.
                try:
                    self.kill_agent()
                    shutil.rmtree(self.work, ignore_errors=True)
                except Exception:
                    pass
            if self.private:
                shutil.rmtree(self.private, ignore_errors=True)
            if self.host_lock is not None:
                os.close(self.host_lock)
                self.host_lock = None
            for sig, handler in handlers.items():
                signal.signal(sig, handler)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise Failure("arguments")


def arguments(argv=None):
    parser = SafeParser(description='Run one factory task')
    for name in ('base-url', 'task-id', 'parameter', 'region', 'model'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        if any(ord(c) < 33 or ord(c) > 126 for c in args.base_url):
            raise ValueError()
        url = urllib.parse.urlsplit(args.base_url)
        if (url.scheme != 'https' or not url.hostname or url.username or url.password
                or url.query or url.fragment or url.path not in ('', '/') or url.port not in (None, 443)):
            raise ValueError()
        if str(uuid.UUID(args.task_id)) != args.task_id:
            raise ValueError()
        if not re.fullmatch(r'/factory/[A-Za-z0-9_./-]{1,900}', args.parameter):
            raise ValueError()
        if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]', args.region):
            raise ValueError()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,127}', args.model):
            raise ValueError()
    except (ValueError, AttributeError):
        raise Failure('arguments') from None
    return args


def main():
    def interrupted(signum, frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        return Runner(arguments()).execute()
    except Exception:
        print('runner failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
