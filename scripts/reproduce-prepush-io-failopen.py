#!/usr/bin/env python3
"""Disposable, synthetic-only probe of the installed pre-push hook.

Never reads credentials or pushes to a remote. Emits classifications/exit codes,
not fixture secret strings. A failing diff-tree models a Git/I/O error; it does
not establish that historical ENOSPC caused the reported incident.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--hook', default=str(Path.home() / '.config/git/hooks/pre-push'))
args = parser.parse_args()
git = shutil.which('git')
if not git:
    raise SystemExit('git unavailable')
base_env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
base_env['GIT_CONFIG_NOSYSTEM'] = '1'
base_env['GIT_CONFIG_GLOBAL'] = '/dev/null'
with tempfile.TemporaryDirectory(prefix='warden-hook-failclosed-') as temp:
    root = Path(temp)
    repo = root / 'repo'
    repo.mkdir()
    def run_git(*argv):
        return subprocess.run([git, '-C', str(repo), *argv], env=base_env,
                              capture_output=True, check=True, timeout=15).stdout.decode().strip()
    run_git('init', '-q', '-b', 'main', '--template=')
    run_git('config', '--local', 'user.name', 'Security Fixture')
    run_git('config', '--local', 'user.email', 'fixture@invalid.example')
    run_git('config', '--local', 'core.hooksPath', '/dev/null')
    f = repo / '.env.dev'
    f.write_text('FIXTURE_MODE=yes\n')
    run_git('add', '--', '.env.dev')
    run_git('commit', '-q', '-m', 'disposable fixture base')
    base = run_git('rev-parse', 'HEAD')
    # Synthetic-only high-confidence provider shape, never a real credential.
    import hashlib
    f.write_text('FIXTURE_TOKEN=' + 'sk-' + 'proj-' + hashlib.sha256(b'public-test-fixture-not-a-credential').hexdigest() + '\n')
    run_git('add', '--', '.env.dev')
    run_git('commit', '-q', '-m', 'disposable fixture secret shape')
    tip = run_git('rev-parse', 'HEAD')
    refs = f'refs/heads/main {tip} refs/heads/main {base}\n'
    def probe(env):
        r = subprocess.run(['sh', str(Path(args.hook).resolve()), 'origin', 'file:///nonexistent-fixture-remote'],
                           cwd=repo, input=refs, text=True, capture_output=True, env=env, timeout=30)
        return {'exit': r.returncode, 'refused': r.returncode != 0,
                'plaintext_warning': 'Possible plaintext' in r.stderr,
                'io_error_observed': 'simulated scan I/O failure' in r.stderr}
    ordinary = probe(base_env)
    bin_dir = root / 'bin'
    bin_dir.mkdir()
    shim = bin_dir / 'git'
    shim.write_text('#!/bin/sh\nfor arg do\n'
                    ' if [ "$arg" = diff-tree ]; then\n'
                    '  echo "simulated scan I/O failure: No space left on device" >&2\n'
                    '  exit 128\n'
                    ' fi\ndone\nexec ' + __import__('shlex').quote(git) + ' "$@"\n')
    shim.chmod(0o700)
    failed_io = probe({**base_env, 'PATH': str(bin_dir) + os.pathsep + base_env.get('PATH', '')})
    print(json.dumps({'synthetic_only': True, 'network_push_performed': False,
                      'normal_scan': ordinary, 'failed_scan': failed_io,
                      'fail_open_reproduced': ordinary['refused'] and not failed_io['refused']}, indent=2))
