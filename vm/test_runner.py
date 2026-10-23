"""Offline runner tests: real local Git, stubbed model/HTTP/privilege boundary."""
import contextlib
import datetime as dt
import errno
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import socket
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

try:
    from vm import runner
except ImportError:
    import runner

TASK = '11111111-1111-4111-8111-111111111111'


def secret(now=None):
    now = now or time.time()
    iso = lambda offset: dt.datetime.fromtimestamp(now + offset, dt.timezone.utc).isoformat()
    return dict(callback_token='c' * 64, github_token='github-private-token',
                model_api_key='model-private-token', expires_at=iso(3600), github_expires_at=iso(7200))


def args():
    return SimpleNamespace(base_url='https://factory.example', task_id=TASK,
                           parameter='/factory/task/attempt', region='us-east-1', model='gpt-6.1')


def slow_transport(connection, *args):
    # Spawned local helper: proves the wall-time cap without network access.
    time.sleep(5)


class FakeHTTP:
    def __init__(self):
        self.calls = []
        self.denied = set()
        self.task = dict(repo_url='https://github.com/example/project',
                         instructions='Edit the file. Literal $(never-run) and `never-run`.',
                         check_command=['python3', '-c', 'from pathlib import Path; Path("file.txt").write_text("mutated by checks")'], model='ignored-model')
        self.pulls = []

    def request(self, method, url, token, body=None, timeout=10):
        self.calls.append((method, url, token, body, timeout))
        endpoint = url.rsplit('/', 1)[-1]
        if endpoint in self.denied:
            raise runner.Failure('http')
        if endpoint == 'assignment':
            return self.task
        if 'api.github.com' in url:
            if method == 'GET':
                return self.pulls
            return {'html_url': 'https://github.com/example/project/pull/7'}
        return None


class FixtureRunner(runner.Runner):
    """Production Git/snapshot/publish methods, local transport and no model calls."""
    def __init__(self, root, *, edit='changed', fail_check=False, **kwargs):
        super().__init__(args(), **kwargs)
        self.fixture = root
        self.edit, self.fail_check = edit, fail_check
        self.operations = []
        self.agent_invocations = []
        self.bundle = secret()

    def validate_host(self):
        pass

    def load_secret(self):
        self.secret = self.bundle
        return min(runner.timestamp(self.secret['expires_at']), runner.timestamp(self.secret['github_expires_at']) - 60)

    def prepare(self):
        self.operations.append('prepare')
        self.private = Path(tempfile.mkdtemp(dir=self.fixture, prefix='private-'))
        self.work = Path(tempfile.mkdtemp(dir=self.fixture, prefix='work-'))
        self.trusted = self.private / 'repository'
        self.source = self.work / 'source'
        self.git_env = runner.clean_env(self.private)
        self.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir='/home/factory-agent')

    def kill_agent(self):
        pass  # Never send signals to the test user's UID.

    def own_tree(self, root):
        pass

    def clone(self, url):
        self.operations.append('clone')
        self.run_process(['git', 'clone', '--quiet', str(self.fixture / 'remote.git'), str(self.trusted)], env=self.git_env)
        self.base = 'main'
        self.initial = self.run_process(['git', '-C', str(self.trusted), 'rev-parse', 'HEAD'], capture=True).decode().strip()
        import shutil
        shutil.copytree(self.trusted, self.source, ignore=shutil.ignore_patterns('.git'))
        self.run_process(['git', '-C', str(self.source), 'init', '--quiet'])
        # File protocol is used only for this offline fixture.
        self.git_env['GIT_CONFIG_COUNT'] = '1'
        self.git_env['GIT_CONFIG_KEY_0'] = 'protocol.file.allow'
        self.git_env['GIT_CONFIG_VALUE_0'] = 'always'

    def git(self, *argv, capture=True, data=None, sink=None):
        # Retain root-owned external git dir, hooks/fsmonitor and isolated config.
        return self.run_process(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                                 '--git-dir=' + str(self.trusted / '.git'), '--work-tree=' + str(self.source),
                                 *argv], capture=capture, env=self.git_env, data=data, sink=sink)

    def unprivileged(self, command, workspace, **kwargs):
        self.agent_invocations.append((command, workspace, kwargs))
        if command[0] == 'codex':
            if self.edit is not None:
                (workspace / 'file.txt').write_text(self.edit)
            if self.edit == 'hostile-config':
                (workspace / '.git' / 'config').write_text('[core]\n hooksPath = /evil\n fsmonitor = /evil\n')
                hooks = workspace / '.git' / 'hooks'
                hooks.mkdir(exist_ok=True)
                hook = hooks / 'pre-commit'
                hook.write_text('#!/bin/sh\ntouch ' + str(self.fixture / 'pwned'))
                hook.chmod(0o755)
        else:
            if self.fail_check:
                command = ['python3', '-c', 'raise SystemExit(1)']
            # Execute local verification, with only privilege isolation stubbed.
            self.run_process(command, cwd=workspace)


class GitFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.remote = self.root / 'remote.git'
        self.seed = self.root / 'seed'
        self.cmd('git', 'init', '--bare', '--initial-branch=main', str(self.remote))
        self.cmd('git', 'init', '--initial-branch=main', str(self.seed))
        (self.seed / 'file.txt').write_text('original')
        self.cmd('git', '-C', str(self.seed), 'add', '.')
        self.cmd('git', '-C', str(self.seed), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@localhost', 'commit', '-m', 'Initial')
        self.cmd('git', '-C', str(self.seed), 'push', str(self.remote), 'main')
        self.http = FakeHTTP()

    def tearDown(self):
        self.temp.cleanup()

    def cmd(self, *command):
        return subprocess.check_output(command, stderr=subprocess.DEVNULL, env=runner.clean_env('/')).decode().strip()

    def execute(self, **kwargs):
        vm = FixtureRunner(self.root, http=self.http, **kwargs)
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            code = vm.execute()
        self.assertNotIn(vm.bundle['github_token'], errors.getvalue())
        return vm, code

    def result(self):
        return json.loads(next(call[3]['result'] for call in self.http.calls if call[1].endswith('/result')))

    def test_happy_snapshot_exact_checks_cannot_mutate_published_tree(self):
        vm, code = self.execute()
        self.assertEqual(code, 0)
        result = self.result()
        self.assertEqual(result['status'], 'pr_created')
        self.assertEqual(result['pr_url'], 'https://github.com/example/project/pull/7')
        self.assertEqual(self.cmd('git', '--git-dir=' + str(self.remote), 'show', result['branch'] + ':file.txt'), 'changed')
        endpoints = [c[1].rsplit('/', 1)[-1] for c in self.http.calls]
        self.assertEqual(endpoints[:2], ['heartbeat', 'assignment'])
        self.assertIn('verifying', endpoints)
        command, _, kw = vm.agent_invocations[0]
        self.assertEqual(command, ['codex', 'exec', '--sandbox', 'workspace-write', '--ephemeral', '--ignore-user-config', '--ignore-rules', '-c', 'approval_policy="never"', '-c', 'sandbox_workspace_write.network_access=false', '-m', 'gpt-6.1', '-'])
        self.assertEqual(kw['prompt'], self.http.task['instructions'])

    def test_failed_checks_never_publish(self):
        _, code = self.execute(fail_check=True)
        self.assertEqual(code, 1)
        self.assertEqual(self.cmd('git', '--git-dir=' + str(self.remote), 'for-each-ref', '--format=%(refname)', 'refs/heads/factory'), '')
        self.assertFalse(any('api.github.com' in c[1] for c in self.http.calls))
        failure = next(c[3] for c in self.http.calls if c[1].endswith('/failure'))
        self.assertEqual(failure, {'reason': 'runner verification failed'})

    def test_no_change_still_checks_no_push_or_pr(self):
        vm, code = self.execute(edit=None)
        self.assertEqual(code, 0)
        self.assertEqual(len(vm.agent_invocations), 2)
        self.assertEqual(self.result()['status'], 'no_changes')
        self.assertFalse(any('api.github.com' in c[1] for c in self.http.calls))

    def test_denied_admission_precedes_all_repository_work(self):
        self.http.denied.add('heartbeat')
        vm, code = self.execute()
        self.assertEqual(code, 1)
        self.assertEqual(vm.operations, [])
        self.assertEqual(len(self.http.calls), 1)

    def test_malicious_assignment_url_never_reaches_git(self):
        self.http.task['repo_url'] = 'https://github.com.evil/example/project'
        vm, code = self.execute()
        self.assertEqual(code, 1)
        self.assertEqual(vm.operations, [])

    def test_expired_admission_precedes_git(self):
        vm = FixtureRunner(self.root, http=self.http, now=lambda: time.time() + 10000)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(vm.execute(), 1)
        self.assertEqual(vm.operations, [])
        self.assertEqual(self.http.calls, [])

    def test_known_secret_rejected_before_checks_or_push(self):
        vm = FixtureRunner(self.root, http=self.http)
        vm.edit = vm.bundle['model_api_key']
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(vm.execute(), 1)
        self.assertEqual(len(vm.agent_invocations), 1)
        self.assertFalse(any('api.github.com' in c[1] for c in self.http.calls))

    def test_agent_git_config_and_hooks_ignored(self):
        _, code = self.execute(edit='hostile-config')
        self.assertEqual(code, 0)
        self.assertFalse((self.root / 'pwned').exists())

    def test_retry_same_commit_and_existing_branch_is_safe(self):
        first = FixtureRunner(self.root, http=self.http)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(first.execute(), 0)
        original = self.result()['commit']
        self.http.calls.clear()
        self.http.pulls = [{'html_url': 'https://github.com/example/project/pull/7', 'state': 'open'}]
        second = FixtureRunner(self.root, http=self.http)
        second.bundle = secret(time.time() + 360)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(second.execute(), 0)
        self.assertEqual(self.result()['commit'], original)

    def test_existing_pr_reused(self):
        self.http.pulls = [{'html_url': 'https://github.com/example/project/pull/2', 'state': 'open'}]
        _, code = self.execute()
        self.assertEqual(code, 0)
        self.assertEqual(self.result()['pr_url'], self.http.pulls[0]['html_url'])
        self.assertFalse(any(c[0] == 'POST' and 'api.github.com' in c[1] for c in self.http.calls))
        self.assertEqual(self.result()['status'], 'pr_existing')

    def test_closed_pr_reused_without_claiming_creation(self):
        self.http.pulls = [{'html_url': 'https://GitHub.com/Example/Project/pull/2', 'state': 'closed'}]
        _, code = self.execute()
        self.assertEqual(code, 0)
        self.assertEqual(self.result()['status'], 'pr_closed')
        self.assertFalse(any(c[0] == 'POST' and 'api.github.com' in c[1] for c in self.http.calls))

    def test_pr_url_cannot_change_fixed_repository_or_host(self):
        for url in ('https://github.com.evil/example/project/pull/7',
                    'https://github.com/example/other/pull/7', 'https://github.com/other/project/pull/7',
                    'https://gıthub.com/example/project/pull/7'):
            self.http.pulls = [{'html_url': url, 'state': 'open'}]
            with self.subTest(url=url):
                _, code = self.execute()
                self.assertEqual(code, 1)

    def test_unchanged_three_mib_blob_is_scanned_and_checked(self):
        (self.seed / 'large.bin').write_bytes(b'x' * (3 * 1024 * 1024))
        self.cmd('git', '-C', str(self.seed), 'add', '.')
        self.cmd('git', '-C', str(self.seed), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@localhost', 'commit', '-m', 'Large file')
        self.cmd('git', '-C', str(self.seed), 'push', str(self.remote), 'main')
        _, code = self.execute(edit=None)
        self.assertEqual(code, 0)
        self.assertEqual(self.result()['status'], 'no_changes')

    def test_hostile_project_codex_rejected_before_model(self):
        config = self.seed / 'nested' / '.codex'
        config.mkdir(parents=True)
        (config / 'config.toml').write_text('sandbox_mode="danger-full-access"\n')
        (config / 'hooks.json').write_text('{"hooks": {"SessionStart": [{"command": "touch pwned"}]}}')
        self.cmd('git', '-C', str(self.seed), 'add', '.')
        self.cmd('git', '-C', str(self.seed), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@localhost', 'commit', '-m', 'Hostile config')
        self.cmd('git', '-C', str(self.seed), 'push', str(self.remote), 'main')
        vm, code = self.execute()
        self.assertEqual(code, 1)
        self.assertEqual(vm.agent_invocations, [])

    def test_ancestor_codex_rejected_before_model(self):
        (self.root / '.codex').mkdir()
        vm, code = self.execute()
        self.assertEqual(code, 1)
        self.assertEqual(vm.agent_invocations, [])

    def test_repository_size_limits_are_checked_before_model(self):
        with patch.object(runner, 'FILE_LIMIT', 3):
            vm, code = self.execute()
        self.assertEqual(code, 1)
        self.assertEqual(vm.agent_invocations, [])

    def test_commit_date_is_stable_base_date_and_not_credential_expiry(self):
        _, code = self.execute()
        self.assertEqual(code, 0)
        date = self.cmd('git', '--git-dir=' + str(self.remote), 'show', '-s', '--format=%ct', self.result()['commit'])
        base = self.cmd('git', '--git-dir=' + str(self.remote), 'show', '-s', '--format=%ct', 'main')
        self.assertEqual(date, base)
        self.assertLessEqual(int(date), time.time())

    def test_future_base_date_preserves_determinism(self):
        future = '@' + str(int(time.time()) + 3600) + ' +0000'
        env = dict(runner.clean_env('/'), GIT_AUTHOR_DATE=future, GIT_COMMITTER_DATE=future)
        subprocess.run(['git', '-C', str(self.seed), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@localhost',
                        'commit', '--quiet', '--allow-empty', '-m', 'Future'], env=env, check=True)
        self.cmd('git', '-C', str(self.seed), 'push', str(self.remote), 'main')
        vm, code = self.execute()
        self.assertEqual(code, 0)
        date = self.cmd('git', '--git-dir=' + str(self.remote), 'show', '-s', '--format=%ct', self.result()['commit'])
        self.assertEqual(date, future.split()[0][1:])

    def test_repeated_signals_are_ignored_during_final_cleanup(self):
        vm = FixtureRunner(self.root, http=self.http)
        cleanup_handlers = []
        before = [runner.signal.getsignal(sig) for sig in (runner.signal.SIGTERM, runner.signal.SIGINT)]
        def kill_agent():
            if vm.lease and vm.lease.stopped.is_set():
                handlers = [runner.signal.getsignal(sig) for sig in (runner.signal.SIGTERM, runner.signal.SIGINT)]
                cleanup_handlers.append(handlers)
                if handlers == [runner.signal.SIG_IGN] * 2:
                    for sig in (runner.signal.SIGTERM, runner.signal.SIGINT):
                        runner.signal.raise_signal(sig)
                        runner.signal.raise_signal(sig)
        vm.kill_agent = kill_agent
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(vm.execute(), 0)
        self.assertEqual(cleanup_handlers, [[runner.signal.SIG_IGN] * 2])
        self.assertEqual([runner.signal.getsignal(sig) for sig in (runner.signal.SIGTERM, runner.signal.SIGINT)], before)

    def test_lost_result_response_can_retry_after_task_becomes_terminal(self):
        original = self.http.request
        terminal = [False]
        def request(method, url, token, body=None, timeout=10):
            endpoint = url.rsplit('/', 1)[-1]
            if endpoint == 'heartbeat' and terminal[0]:
                raise runner.HTTPFailure(False)
            if endpoint == 'result' and not terminal[0]:
                terminal[0] = True
                time.sleep(0.3)
                raise runner.HTTPFailure(True)
            return original(method, url, token, body, timeout)
        self.http.request = request
        lease_type = runner.Lease
        def fast_lease(callback, deadline, now):
            return lease_type(callback, deadline, now, interval=0.01)
        with patch.object(runner, 'Lease', side_effect=fast_lease):
            _, code = self.execute()
        self.assertEqual(code, 0)
        self.assertEqual(self.result()['status'], 'pr_created')

    def test_transient_admission_verifying_and_result_are_retried(self):
        original = self.http.request
        failures = {'heartbeat', 'verifying', 'result'}
        attempts = []
        def flaky(method, url, token, body=None, timeout=10):
            endpoint = url.rsplit('/', 1)[-1]
            attempts.append((endpoint, body))
            if endpoint in failures:
                failures.remove(endpoint)
                raise runner.HTTPFailure(True)
            return original(method, url, token, body, timeout)
        self.http.request = flaky
        _, code = self.execute()
        self.assertEqual(code, 0)
        self.assertFalse(failures)
        results = [body for endpoint, body in attempts if endpoint == 'result']
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])

    def test_branch_collision_does_not_overwrite(self):
        self.cmd('git', '-C', str(self.seed), 'push', str(self.remote), 'HEAD:refs/heads/factory/task-' + TASK)
        _, code = self.execute()
        self.assertEqual(code, 1)
        self.assertEqual(self.cmd('git', '--git-dir=' + str(self.remote), 'rev-parse', 'factory/task-' + TASK), self.cmd('git', '--git-dir=' + str(self.remote), 'rev-parse', 'main'))


class StreamingTests(unittest.TestCase):
    def test_real_git_index_over_two_mib_and_single_batch_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            env = runner.clean_env(folder)
            subprocess.run(['git', 'init', '--quiet', folder], env=env, check=True)
            oid = subprocess.check_output(['git', '-C', folder, 'hash-object', '-w', '--stdin'],
                                          input=b'contents', env=env).strip()
            index = b''.join(b'100644 ' + oid + b'\t' + str(i).encode() + b'x' * 110 + b'\n' for i in range(18000))
            subprocess.run(['git', '-C', folder, 'update-index', '--index-info'], input=index, env=env, check=True)
            entries = runner.StagedEntries(lambda: None)
            runner.Processes().run(['git', '-C', folder, 'ls-files', '--stage', '-z'], env=env, sink=entries.feed)
            entries.finish()
            self.assertGreater(len(index), runner.LIMIT)
            self.assertEqual(entries.count, 18000)
            self.assertEqual(entries.oids, {oid: 18000})
            blobs = runner.StagedBlobs(entries.oids, [b'private-token'], lambda: None)
            runner.Processes().run(['git', '-C', folder, 'cat-file', '--batch'], env=env, data=oid + b'\n', sink=blobs.feed)
            blobs.finish()
            self.assertEqual(blobs.total, 8 * 18000)

    def test_file_and_tree_limits_include_duplicate_blob_paths(self):
        oid = b'a' * 40
        header = oid + b' blob ' + str(runner.FILE_LIMIT).encode() + b'\n'
        blobs = runner.StagedBlobs({oid: 16}, [b'private-token'], lambda: None)
        blobs.feed(header)
        for _ in range(runner.FILE_LIMIT // 65536):
            blobs.feed(b'x' * 65536)
        blobs.feed(b'\n')
        blobs.finish()
        self.assertEqual(blobs.total, runner.TREE_LIMIT)
        for count, size in ((17, runner.FILE_LIMIT), (1, runner.FILE_LIMIT + 1)):
            blobs = runner.StagedBlobs({oid: count}, [b'private-token'], lambda: None)
            with self.subTest(count=count, size=size), self.assertRaises(runner.Failure):
                blobs.feed(oid + b' blob ' + str(size).encode() + b'\n')

    def test_secret_scanning_crosses_chunks_but_not_blob_boundaries(self):
        a, b = b'a' * 40, b'b' * 40
        blobs = runner.StagedBlobs({a: 1}, [b'private-token'], lambda: None)
        blobs.feed(a + b' blob 13\nprivate-')
        with self.assertRaises(runner.Failure):
            blobs.feed(b'token\n')
        blobs = runner.StagedBlobs({a: 1, b: 1}, [b'private-token'], lambda: None)
        stream = a + b' blob 8\nprivate-\n' + b + b' blob 5\ntoken\n'
        for byte in stream:
            blobs.feed(bytes([byte]))
        blobs.finish()

    def test_stream_protocol_truncation_and_count_limit_fail_closed(self):
        oid = b'a' * 40
        for entry in (b'120000 ' + oid + b' 0\tlink\0', b'100644 ' + oid + b' 1\tconflict\0', b'x' * 8193):
            with self.subTest(entry=entry[:10]), self.assertRaises(runner.Failure):
                runner.StagedEntries(lambda: None).feed(entry)
        entries = runner.StagedEntries(lambda: None)
        entry = b'100644 ' + oid + b' 0\tfile\0'
        for _ in range(100):
            entries.feed(entry * 1000)
        self.assertEqual(entries.count, runner.FILE_COUNT)
        with self.assertRaises(runner.Failure):
            entries.feed(entry)
        blobs = runner.StagedBlobs({oid: 1}, [b'private-token'], lambda: None)
        blobs.feed(oid + b' blob 3\nab')
        with self.assertRaises(runner.Failure):
            blobs.finish()


class BoundaryTests(unittest.TestCase):
    def test_embedded_runner_leaves_four_kib_for_shell_and_arguments(self):
        self.assertLess(len(Path(runner.__file__).read_bytes()) + 4096, 50 * 1024)

    def test_metadata_firewall_requires_first_exact_rule_for_both_families(self):
        rules = {
            'iptables': b'-P OUTPUT ACCEPT\n-A OUTPUT -d 169.254.169.254/32 -m owner --uid-owner 1234 -j REJECT --reject-with icmp-port-unreachable\n',
            'ip6tables': b'-P OUTPUT ACCEPT\n-A OUTPUT -d fd00:ec2::254/128 -m owner --uid-owner 1234 -j REJECT --reject-with icmp6-port-unreachable\n'}
        calls = []
        class Processes:
            def run(self, command, **kwargs):
                calls.append(command)
                return rules.get(command[0], b'')
        vm = runner.Runner(args(), processes=Processes())
        vm.account = SimpleNamespace(pw_uid=1234, pw_gid=1234)
        vm.verify_metadata_firewall()
        self.assertEqual([c[0] for c in calls], ['iptables', 'ip6tables', 'setpriv'])
        self.assertTrue(all('-S' in c and '-I' not in c for c in calls[:2]))
        for tool in rules:
            original = rules[tool]
            for bad in (b'-P OUTPUT ACCEPT\n',
                        original.replace(b'-A OUTPUT', b'-A OUTPUT -j ACCEPT\n-A OUTPUT', 1),
                        original.replace(b'1234', b'1235'),
                        original.replace(b'-j REJECT', b'-p tcp -j REJECT')):
                with self.subTest(tool=tool, bad=bad), self.assertRaises(runner.Failure):
                    rules[tool] = bad
                    vm.verify_metadata_firewall()
            rules[tool] = original

    def test_metadata_probe_rejects_timeout_or_success(self):
        commands = []
        vm = runner.Runner(args())
        vm.account = SimpleNamespace(pw_uid=1234, pw_gid=1234)
        def run(command, **kwargs):
            commands.append(command)
            if command[0] == 'iptables':
                return b'-A OUTPUT -d 169.254.169.254/32 -m owner --uid-owner 1234 -j REJECT --reject-with icmp-port-unreachable\n'
            if command[0] == 'ip6tables':
                return b'-A OUTPUT -d fd00:ec2::254/128 -m owner --uid-owner 1234 -j REJECT --reject-with icmp6-port-unreachable\n'
        vm.run_process = run
        vm.verify_metadata_firewall()
        probe = commands[-1][-1]
        for result in (errno.ECONNREFUSED, errno.ENETUNREACH, errno.ETIMEDOUT, 0):
            with self.subTest(result=result), patch.object(socket, 'socket') as sock:
                sock.return_value.__enter__.return_value.connect_ex.return_value = result
                if result in (0, errno.ETIMEDOUT):
                    with self.assertRaises(SystemExit):
                        exec(probe, {})
                else:
                    exec(probe, {})
                    self.assertEqual(sock.call_count, 2)

    def test_host_lock_waits_for_previous_runner_and_is_bounded(self):
        vm = runner.Runner(args())
        with patch.object(runner.os, 'open', return_value=42), patch.object(runner.fcntl, 'flock', side_effect=[BlockingIOError(), None]) as flock, patch.object(runner.time, 'sleep') as sleep:
            vm.acquire_host_lock()
            self.assertEqual(flock.call_count, 2)
            sleep.assert_called_once_with(0.1)
        with patch.object(runner.os, 'open', return_value=42), patch.object(runner.fcntl, 'flock', side_effect=BlockingIOError()), patch.object(runner.time, 'monotonic', side_effect=[0, runner.LOCK_WAIT + 1]):
            with self.assertRaises(runner.Failure):
                vm.acquire_host_lock()

    def test_proc_disappearance_is_benign_but_permission_failure_is_not(self):
        vm = runner.Runner(args(), processes=SimpleNamespace(run=lambda *a, **kw: b''))
        vm.account, vm.uid_owned = SimpleNamespace(pw_uid=1234), True
        for error in (FileNotFoundError(), ProcessLookupError()):
            with patch.object(Path, 'iterdir', return_value=iter([Path('/proc/123')])), patch.object(Path, 'read_text', side_effect=error):
                vm.kill_agent()
        with patch.object(Path, 'iterdir', return_value=iter([Path('/proc/123')])), patch.object(Path, 'read_text', side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                vm.kill_agent()

    def test_http_error_types_do_not_include_response_or_authorization(self):
        vm = runner.HTTP()
        for error, retryable in ((runner.urllib.error.HTTPError('private-url', 503, 'private-body', {}, None), True),
                                 (runner.urllib.error.HTTPError('private-url', 403, 'private-body', {}, None), False),
                                 (runner.urllib.error.URLError('private-transport'), True),
                                 (ValueError('private-json'), False)):
            with self.subTest(error=type(error)), patch.object(vm.opener, 'open', side_effect=error):
                with self.assertRaises(runner.HTTPFailure) as caught:
                    vm._request('POST', 'https://unused.example', 'private-token')
                self.assertEqual(caught.exception.retryable, retryable)
                self.assertEqual(str(caught.exception), 'http')

    def test_retry_budget_and_authorization_rejection(self):
        for retryable, expected in ((True, 3), (False, 1)):
            http = SimpleNamespace(request=unittest.mock.Mock(side_effect=runner.HTTPFailure(retryable)))
            vm = runner.Runner(args(), http=http)
            with self.subTest(retryable=retryable), self.assertRaises(runner.HTTPFailure):
                vm.request('POST', 'https://unused.example', 'private', retry=True)
            self.assertEqual(http.request.call_count, expected)

    def test_revocation_during_retry_aborts_before_next_request(self):
        vm = runner.Runner(args())
        vm.lease = runner.Lease(lambda: None, time.time() + 60)
        def revoked(*args, **kwargs):
            vm.lease.rejected.set()
            raise runner.HTTPFailure(True)
        vm.http = SimpleNamespace(request=unittest.mock.Mock(side_effect=revoked))
        with self.assertRaises(runner.Failure):
            vm.request('POST', 'https://unused.example', 'private', retry=True)
        self.assertEqual(vm.http.request.call_count, 1)

    def test_ongoing_transient_heartbeat_is_not_retried(self):
        http = SimpleNamespace(request=unittest.mock.Mock(side_effect=[None, runner.HTTPFailure(True)]))
        vm = runner.Runner(args(), http=http)
        vm.secret, vm.task_url = secret(), 'https://unused.example/task'
        vm.lease = runner.Lease(lambda: vm.callback('heartbeat', retry=vm.lease.thread is None), time.time() + 60, interval=0.01)
        vm.lease.start()
        try:
            self.assertTrue(vm.lease.rejected.wait(1))
            self.assertEqual(http.request.call_count, 2)
        finally:
            vm.lease.close()

    def test_repository_urls(self):
        self.assertEqual(runner.repository('https://github.com/owner/repo.git'), ('owner', 'repo', 'https://github.com/owner/repo.git'))
        for url in ['http://github.com/a/b', 'https://github.com.evil/a/b', 'https://github.com/a/b?x=y',
                    'https://user@github.com/a/b', 'https://github.com/a/../b', 'https://github.com/a/b/',
                    'https://github.com/a/b#fragment', 'https://github.com:443/a/b', 'https://github.com/a/%62',
                    'https://github.com/a/b\n', 'https://github.com/a/.git']:
            with self.subTest(url=url), self.assertRaises(runner.Failure):
                runner.repository(url)

    def test_assignment_requires_trusted_argv(self):
        for command in [None, [], 'make test', [''], ['x\0y'], ['x'] * 65, ['x' * 4097], ['x' * 4096] * 5]:
            with self.subTest(command=command), self.assertRaises(runner.Failure):
                runner.assignment(dict(repo_url='https://github.com/a/b', instructions='Do work', check_command=command))

    def test_assignment_matches_api_limits(self):
        value = dict(repo_url='https://github.com/owner/.github', instructions='x' * 65536,
                     check_command=['program', ''])
        self.assertEqual(runner.assignment(value), value)
        value['instructions'] += 'x'
        with self.assertRaises(runner.Failure):
            runner.assignment(value)

    def test_lease_revocation_and_expiry(self):
        clock = [100]
        lease = runner.Lease(lambda: None, 150, now=lambda: clock[0])
        lease.beat()
        clock[0] = 131
        with self.assertRaises(runner.Failure):
            lease.guard()
        clock[0] = 100
        lease.callback = lambda: (_ for _ in ()).throw(RuntimeError('sensitive'))
        with self.assertRaises(runner.Failure):
            lease.beat()
        self.assertTrue(lease.rejected.is_set())
        clock[0] = 151
        with self.assertRaises(runner.Failure):
            lease.guard()

    def test_ongoing_heartbeat_rejection_aborts(self):
        calls = []
        def callback():
            calls.append(1)
            if len(calls) > 1:
                raise runner.Failure('http')
        lease = runner.Lease(callback, time.time() + 60, interval=0.01)
        lease.start()
        try:
            self.assertTrue(lease.rejected.wait(1))
            with self.assertRaises(runner.Failure):
                lease.guard()
        finally:
            lease.close()

    def test_symlink_and_special_file_rejected(self):
        vm = runner.Runner(args())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'escape').symlink_to('/etc')
            with self.assertRaises(runner.Failure):
                vm.validate_tree(root)
            (root / 'escape').unlink()
            os.mkfifo(root / 'fifo')
            with self.assertRaises(runner.Failure):
                vm.validate_tree(root)
            with self.assertRaises(runner.Failure):
                vm.validate_tree(root / 'fifo')

    def test_cli_and_environment_are_fixed_and_private(self):
        captured = []
        class Processes:
            def run(self, command, **kwargs):
                captured.append((command, kwargs))
                return b''
        vm = runner.Runner(args(), processes=Processes())
        vm.secret = secret()
        vm.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir='/home/factory-agent')
        vm.kill_agent = lambda: None
        with tempfile.TemporaryDirectory() as folder:
            vm.work = Path(folder)
            vm.unprivileged(['codex', 'exec'], vm.work, prompt='literal $(bad)', model=True, network=True)
            vm.unprivileged(['python3', '-c', 'pass'], vm.work, network=False)
        agent, check = captured
        self.assertEqual(agent[0][:5], ['unshare', '--mount', '--propagation', 'private', '--'])
        self.assertIn('--bounding-set=-all', agent[0])
        self.assertEqual(agent[1]['data'], b'literal $(bad)')
        self.assertEqual(agent[1]['env']['CODEX_API_KEY'], vm.secret['model_api_key'])
        self.assertNotIn('CODEX_API_KEY', check[1]['env'])
        self.assertEqual(check[0][:6], ['unshare', '--mount', '--propagation', 'private', '--net', '--'])
        self.assertIn('/tmp', check[0])
        self.assertIn('/dev/shm', check[0])
        self.assertIn('/home/factory-agent', check[0])
        self.assertIn(str(vm.work / 'model-home'), check[0])
        # Exercise the fixed namespace launcher with mount/exec stubbed, never
        # touching host mounts. Its argv is independent of repository content.
        index = check[0].index('-c')
        with patch.object(runner.sys, 'argv', ['-c', *check[0][index + 2:]]), patch.object(subprocess, 'run') as mount, patch.object(os, 'execvpe') as execute:
            exec(check[0][index + 1], {})
            self.assertEqual([call.args[0][-1] for call in mount.call_args_list],
                             ['/tmp', '/var/tmp', '/dev/shm', '/home/factory-agent', str(vm.work / 'model-home')])
            self.assertTrue(all(call.kwargs['check'] for call in mount.call_args_list))
            self.assertEqual(execute.call_args.args[0], 'setpriv')
        for key in ('AWS_ACCESS_KEY_ID', 'GITHUB_TOKEN', 'SSH_AUTH_SOCK'):
            self.assertNotIn(key, agent[1]['env'])

    def test_process_output_and_deadline_bounded(self):
        process = runner.Processes()
        with self.assertRaises(runner.Failure):
            process.run(['python3', '-c', 'print("x" * 3000000)'], env=runner.clean_env('/'), capture=True)
        start = time.monotonic()
        with self.assertRaises(runner.Failure):
            process.run(['python3', '-c', 'import time; time.sleep(10)'], env=runner.clean_env('/'), timeout=0.1)
        self.assertLess(time.monotonic() - start, 2)

    def test_ssm_argv_and_invalid_credentials(self):
        class Processes:
            def run(self, command, **kwargs):
                self.command, self.kwargs = command, kwargs
                return json.dumps(self.bundle).encode()
        process = Processes()
        process.bundle = secret()
        vm = runner.Runner(args(), processes=process)
        vm.load_secret()
        self.assertEqual(process.command, ['aws', 'ssm', 'get-parameter', '--name', args().parameter,
                                          '--region', args().region, '--with-decryption', '--query', 'Parameter.Value', '--output', 'text'])
        self.assertTrue(process.kwargs['capture'])
        for key, value in [('callback_token', 'bad'), ('github_token', ''), ('model_api_key', '\n'),
                           ('expires_at', 'never'), ('github_expires_at', None)]:
            process.bundle = dict(secret(), **{key: value})
            with self.subTest(key=key), self.assertRaises(runner.Failure):
                vm.load_secret()

    def test_argument_errors_never_echo_input(self):
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(runner.Failure):
                runner.arguments(['--secret-value'])
        self.assertEqual(errors.getvalue(), '')

    def test_http_has_total_wall_time_limit_without_network(self):
        start = time.monotonic()
        with patch.object(runner, '_http_worker', slow_transport):
            with self.assertRaises(runner.Failure):
                runner.HTTP().request('GET', 'https://unused.example', 'private', timeout=0.2)
        self.assertLess(time.monotonic() - start, 2)

    def test_lease_rejection_kills_active_process(self):
        lease = runner.Lease(lambda: None, time.time() + 60)
        timer = runner.threading.Timer(0.1, lease.rejected.set)
        timer.start()
        start = time.monotonic()
        try:
            with self.assertRaises(runner.Failure):
                runner.Processes().run(['python3', '-c', 'import time; time.sleep(10)'],
                                       env=runner.clean_env('/'), guard=lease.guard)
        finally:
            timer.cancel()
        self.assertLess(time.monotonic() - start, 2)

    def test_redirect_refused(self):
        with self.assertRaises(runner.Failure):
            runner.NoRedirect().redirect_request(None, None, 302, None, None, 'https://evil.test')


if __name__ == '__main__':
    unittest.main()
