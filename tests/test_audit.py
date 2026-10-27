import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('audit',ROOT/'scripts/audit.py')
audit=importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def scan_temp(dockerfile, extras=None, ignore=None):
    with tempfile.TemporaryDirectory() as d:
        r=Path(d)
        (r/'Dockerfile').write_text(dockerfile)
        for name in (extras or []):
            p=r/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('dummy\n')
        if ignore is not None:(r/'.dockerignore').write_text(ignore)
        return audit.scan(r)


def rules(*args,**kwargs):return {f['rule'] for f in scan_temp(*args,**kwargs)}


class DockerContextTests(unittest.TestCase):
    def test_arg_token(self):self.assertIn('DC001',rules('FROM scratch\nARG NPM_TOKEN\n'))
    def test_env_token(self):self.assertIn('DC001',rules('FROM scratch\nENV API_KEY=fixture\n'))
    def test_env_no_sensitive_variable(self):self.assertNotIn('DC001',rules('FROM scratch\nENV PORT=5000\n'))
    def test_env_legacy_form(self):self.assertIn('DC001',rules('FROM scratch\nENV PASSWORD placeholder\n'))
    def test_copy_all(self):self.assertIn('DC002',rules('FROM scratch\nCOPY . /opt/app\n'))
    def test_copy_subdir(self):self.assertNotIn('DC002',rules('FROM scratch\nCOPY src /app\n'))
    def test_copy_from_stage(self):self.assertNotIn('DC002',rules('FROM scratch\nCOPY --from=builder . /app\n'))
    def test_missing_dockerignore(self):self.assertIn('DC003',rules('FROM scratch\nCOPY . /app\n'))
    def test_present_dockerignore(self):self.assertNotIn('DC003',rules('FROM scratch\nCOPY . /app\n',ignore='.env\n'))
    def test_env_file_included(self):self.assertIn('DC005',rules('FROM scratch\nCOPY src /app\n',extras=['.env.production']))
    def test_env_example_not_secret(self):self.assertNotIn('DC005',rules('FROM scratch\n',extras=['.env.example']))
    def test_private_key_included(self):self.assertIn('DC005',rules('FROM scratch\n',extras=['tls/key.pem']))
    def test_env_excluded(self):self.assertNotIn('DC005',rules('FROM scratch\n',extras=['.env.production'],ignore='.env*'))
    def test_negated_last_rule(self):self.assertIn('DC005',rules('FROM scratch\n',extras=['.env.production'],ignore='.env*\n!.env.production\n'))
    def test_order_override(self):self.assertNotIn('DC005',rules('FROM scratch\n',extras=['.env.production'],ignore='!.env.production\n.env*\n'))
    def test_git_directory_finding(self):self.assertIn('DC004',rules('FROM scratch\nCOPY . .\n',extras=['.git/config']))
    def test_git_ignored(self):self.assertNotIn('DC004',rules('FROM scratch\nCOPY . .\n',extras=['.git/config'],ignore='.git'))
    def test_dockerfile_specific_ignore_precedence(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);(r/'Dockerfile').write_text('FROM scratch\nCOPY . .\n');(r/'.env').write_text('test')
            (r/'.dockerignore').write_text('.env\n');(r/'Dockerfile.dockerignore').write_text('*.md\n')
            self.assertIn('DC005',{f['rule'] for f in audit.scan(r)})
    def test_multiline_arg(self):self.assertIn('DC001',rules('FROM scratch\nENV \\\n ACCESS_TOKEN=abc\n'))
    def test_json_copy(self):self.assertIn('DC002',rules('FROM scratch\nCOPY [".","/app"]\n'))
    def test_safe_example(self):self.assertEqual(audit.scan(ROOT/'examples/safe'),[])
    def test_unsafe_example(self):self.assertGreaterEqual(len(audit.scan(ROOT/'examples/unsafe')),4)


class SafetyTests(unittest.TestCase):
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);r.joinpath('Dockerfile').symlink_to(ROOT/'examples/safe/Dockerfile')
            self.assertEqual(audit.scan(r),[])
    def test_dockerfile_oversize(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);r.joinpath('Dockerfile').write_text('x'*(audit.MAX_DOCKERFILE_BYTES+1))
            with self.assertRaises(audit.InputError):audit.scan(r)
    def test_cli_fail_on_high(self):
        p=subprocess.run([sys.executable,str(ROOT/'scripts/audit.py'),str(ROOT/'examples/unsafe'),'--format','json'],capture_output=True,text=True)
        self.assertEqual(p.returncode,2)
        self.assertGreaterEqual(json.loads(p.stdout)['count'],4)
    def test_cli_safe_exit(self):
        p=subprocess.run([sys.executable,str(ROOT/'scripts/audit.py'),str(ROOT/'examples/safe'),'--format','json'],capture_output=True,text=True)
        self.assertEqual(p.returncode,0)

if __name__=='__main__':unittest.main()
