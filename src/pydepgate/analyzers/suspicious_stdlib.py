"""
Detects use of dangerous stdlib functions in startup-vector files.

This analyzer fires on calls to stdlib functions that are commonly
used in supply-chain attacks: process spawning, network access, and
native code loading. The signals fire broadly; the rules engine
decides whether specific contexts make a signal HIGH/CRITICAL or
INFO.

Three signal types:

  STDLIB001: process spawning (subprocess, os.system, os.exec*, fork)
  STDLIB002: network access (urllib, socket, http.client, ftplib, etc.)
  STDLIB003: native code loading (ctypes.CDLL, WinDLL, dlopen, etc.)

Each signal carries the specific function name in its context, plus
scope information. Rules can match on signal_id alone (broad) or
combine with file_kind, scope, and context_contains for precision.

Note: this analyzer only sees files that triage classifies as
in-scope (setup.py, __init__.py, .pth, sitecustomize, etc.). It does
not scan arbitrary library files.
"""

from __future__ import annotations

import ast
from typing import Iterable

from pydepgate.analyzers.base import (
    Analyzer, Confidence, Scope, Signal,
)
from pydepgate.analyzers._visitor import _ScopeTracker, get_qualified_name
from pydepgate.parsers.pysource import ParsedPySource, SourceLocation


# -----------------------------------------------------------------------------
# Process spawning (STDLIB001)
# -----------------------------------------------------------------------------
# Functions whose calls represent spawning a new process or executing
# a shell command. The dotted form is what get_qualified_name returns
# for the most common usage; aliased imports may not be caught.

_PROCESS_SPAWN_FUNCTIONS = frozenset({
    # subprocess module
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",

    # os module - direct execution
    "os.system",
    "os.popen",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.fork",
    "os.forkpty",

    # pty module
    "pty.spawn",
    "pty.fork",

    # platform module - shell execution
    "platform.popen",
})


# -----------------------------------------------------------------------------
# Network access (STDLIB002)
# -----------------------------------------------------------------------------

_NETWORK_FUNCTIONS = frozenset({
    # urllib (Python 3 layout)
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "urllib.request.Request",
    "urllib.urlopen",  # legacy fallback

    # socket module
    "socket.socket",
    "socket.create_connection",
    "socket.create_server",

    # http.client
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",

    # ftplib, telnetlib, etc.
    "ftplib.FTP",
    "ftplib.FTP_TLS",
    "telnetlib.Telnet",
    "smtplib.SMTP",
    "smtplib.SMTP_SSL",
    "imaplib.IMAP4",
    "imaplib.IMAP4_SSL",
    "poplib.POP3",
    "poplib.POP3_SSL",
    "nntplib.NNTP",

    # requests-like patterns sometimes appear in shimmed code
    "http.server.HTTPServer",
    "http.server.BaseHTTPRequestHandler",

    # Lower-level
    "ssl.create_default_context",  # Often paired with socket creation
})


# -----------------------------------------------------------------------------
# Native code loading (STDLIB003)
# -----------------------------------------------------------------------------

_NATIVE_LOAD_FUNCTIONS = frozenset({
    "ctypes.CDLL",
    "ctypes.WinDLL",
    "ctypes.OleDLL",
    "ctypes.PyDLL",
    "ctypes.cdll.LoadLibrary",
    "ctypes.windll.LoadLibrary",
    "ctypes.oledll.LoadLibrary",
    "ctypes.pydll.LoadLibrary",
})


# -----------------------------------------------------------------------------
# The analyzer
# -----------------------------------------------------------------------------

class SuspiciousStdlibAnalyzer(Analyzer):
    """Detects calls to dangerous stdlib functions."""

    @property
    def name(self) -> str:
        return "suspicious_stdlib"

    def analyze_python(self, parsed: ParsedPySource) -> Iterable[Signal]:
        if not parsed.is_parseable:
            return ()
        visitor = _Visitor()
        visitor.visit(parsed.ast_tree)
        return visitor.signals


class _Visitor(_ScopeTracker):
    """AST visitor for suspicious_stdlib detection."""

    def __init__(self) -> None:
        super().__init__()
        self.signals: list[Signal] = []

    def visit_Call(self, node: ast.Call) -> None:
        self._check_process_spawn(node)
        self._check_network(node)
        self._check_native_load(node)
        self.generic_visit(node)

    def _check_process_spawn(self, node: ast.Call) -> None:
        name = get_qualified_name(node.func)
        if name is None:
            return
        if name not in _PROCESS_SPAWN_FUNCTIONS:
            return
        self._emit(node, "STDLIB001", "process_spawn", name)

    def _check_network(self, node: ast.Call) -> None:
        name = get_qualified_name(node.func)
        if name is None:
            return
        if name not in _NETWORK_FUNCTIONS:
            return
        self._emit(node, "STDLIB002", "network", name)

    def _check_native_load(self, node: ast.Call) -> None:
        name = get_qualified_name(node.func)
        if name is None:
            return
        if name not in _NATIVE_LOAD_FUNCTIONS:
            return
        self._emit(node, "STDLIB003", "native_load", name)

    def _emit(
        self,
        node: ast.Call,
        signal_id: str,
        category: str,
        function_name: str,
    ) -> None:
        """Build a Signal for a matched dangerous call."""
        # Confidence is HIGH (70) so mechanical mapping yields MEDIUM.
        # Rules can promote specific contexts to HIGH or CRITICAL.
        description_map = {
            "STDLIB001": (
                f"call to {function_name}() spawns a subprocess or "
                f"executes a shell command"
            ),
            "STDLIB002": (
                f"call to {function_name}() initiates network "
                f"communication"
            ),
            "STDLIB003": (
                f"call to {function_name}() loads native code via ctypes"
            ),
        }
        self.signals.append(Signal(
            analyzer="suspicious_stdlib",
            signal_id=signal_id,
            confidence=Confidence.HIGH,
            scope=self.current_scope,
            location=SourceLocation(line=node.lineno, column=node.col_offset),
            description=description_map[signal_id],
            context={
                "category": category,
                "function": function_name,
                "scope_name": self.current_scope.name.lower(),
            },
        ))