"""Fuzzing tools for Strix.

Provides tools for:
- AFL++ fuzzing (launch, status, crash analysis)
- boofuzz for network protocol fuzzing
- Crash triage and minimization
- Corpus generation
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

try:
    from agents import function_tool, RunContextWrapper
    _HAS_AGENTS = True
except ImportError:
    _HAS_AGENTS = False

logger = logging.getLogger(__name__)


def _run(cmd: list[str], cwd: str = "", timeout: int = 30, env: dict | None = None) -> tuple[str, str, int]:
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd or None,
            env={**os.environ, **(env or {})},
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127
    except Exception as e:
        return "", str(e), 1


if _HAS_AGENTS:

    @function_tool
    async def afl_fuzz_start(
        ctx: RunContextWrapper,
        binary_path: str,
        input_dir: str,
        output_dir: str,
        binary_args: str = "@@",
        parallel_jobs: int = 1,
        timeout_ms: int = 5000,
        memory_limit_mb: int = 256,
        extra_args: str = "",
    ) -> str:
        """Start AFL++ fuzzing session in background.

        Args:
            binary_path: Path to instrumented binary (compiled with afl-cc/afl-clang-fast)
            input_dir: Corpus/seed input directory
            output_dir: AFL++ output directory for findings
            binary_args: Binary arguments, @@ is replaced by AFL with input file path
            parallel_jobs: Number of parallel fuzzer instances (1=single, >1=master+slaves)
            timeout_ms: Per-run timeout in milliseconds
            memory_limit_mb: Memory limit per instance (0=none)
            extra_args: Additional afl-fuzz flags
        """
        if not shutil.which("afl-fuzz"):
            return (
                "AFL++ not installed.\n"
                "Install on Debian/Ubuntu: apt install afl++\n"
                "Or build from source: https://github.com/AFLplusplus/AFLplusplus\n"
                "Don't forget to instrument your binary first:\n"
                "  CC=afl-cc ./configure && make\n"
                "  # or: afl-clang-fast -o target target.c"
            )

        inp = Path(input_dir)
        out = Path(output_dir)

        if not inp.exists():
            return f"Input directory not found: {input_dir}"

        out.mkdir(parents=True, exist_ok=True)

        bin_parts = binary_args.split()

        def build_cmd(instance_id: str, is_master: bool) -> list[str]:
            cmd = [
                "afl-fuzz",
                "-i", str(inp),
                "-o", str(out),
                "-t", str(timeout_ms),
            ]
            if memory_limit_mb > 0:
                cmd.extend(["-m", str(memory_limit_mb)])
            if parallel_jobs > 1:
                flag = "-M" if is_master else "-S"
                cmd.extend([flag, instance_id])
            if extra_args:
                cmd.extend(extra_args.split())
            cmd.append("--")
            cmd.append(binary_path)
            cmd.extend(bin_parts)
            return cmd

        if parallel_jobs == 1:
            cmd = build_cmd("fuzzer01", True)
            cmd_str = " ".join(cmd)
            return (
                f"AFL++ command (run in background):\n\n"
                f"  nohup {cmd_str} > /tmp/afl.log 2>&1 &\n\n"
                f"Monitor with:\n"
                f"  afl-whatsup {output_dir}\n"
                f"  watch -n 5 'afl-whatsup {output_dir}'\n\n"
                f"Check crashes:\n"
                f"  ls {output_dir}/default/crashes/"
            )

        # Build all instance commands
        cmds = []
        for i in range(parallel_jobs):
            iid = f"fuzzer{i+1:02d}"
            is_master = (i == 0)
            cmds.append(" ".join(build_cmd(iid, is_master)))

        return (
            f"AFL++ parallel fuzzing ({parallel_jobs} instances):\n\n"
            + "\n".join(f"  nohup {c} > /tmp/afl_{i+1}.log 2>&1 &" for i, c in enumerate(cmds))
            + f"\n\nMonitor:\n  watch -n 5 'afl-whatsup {output_dir}'"
            + f"\n\nCheck crashes:\n  ls {output_dir}/fuzzer01/crashes/"
        )

    @function_tool
    async def afl_fuzz_status(
        ctx: RunContextWrapper,
        output_dir: str,
    ) -> str:
        """Check AFL++ fuzzing status and crash count.

        Args:
            output_dir: AFL++ output directory
        """
        if not shutil.which("afl-whatsup"):
            return "afl-whatsup not installed. Install AFL++: apt install afl++"

        stdout, stderr, rc = _run(["afl-whatsup", output_dir])
        if rc != 0:
            return f"Error: {stderr}\nIs AFL++ running? Check output dir: {output_dir}"
        return stdout or "No output from afl-whatsup"

    @function_tool
    async def afl_triage_crashes(
        ctx: RunContextWrapper,
        binary_path: str,
        crash_dir: str,
        binary_args: str = "@@",
        limit: int = 10,
    ) -> str:
        """Triage AFL++ crash files to find unique crashes.

        Args:
            binary_path: Path to the target binary
            crash_dir: AFL++ crashes directory, e.g. output/default/crashes/
            binary_args: Binary arguments (@@ = input file)
            limit: Max crashes to analyze
        """
        cdir = Path(crash_dir)
        if not cdir.exists():
            return f"Crash directory not found: {crash_dir}"

        crashes = [f for f in cdir.iterdir() if f.is_file() and f.name != "README.txt"]
        if not crashes:
            return f"No crash files found in {crash_dir}"

        results = []
        for crash_file in crashes[:limit]:
            cmd = binary_args.replace("@@", str(crash_file)).split()
            full_cmd = [binary_path] + cmd if "@@" in binary_args else [binary_path]

            stdout, stderr, rc = _run(full_cmd, timeout=10)
            signal_name = ""
            if rc < 0:
                import signal
                try:
                    signal_name = signal.Signals(-rc).name
                except Exception:
                    signal_name = f"signal {-rc}"
            results.append({
                "file": crash_file.name,
                "size": crash_file.stat().st_size,
                "exit_code": rc,
                "signal": signal_name,
                "stderr_snippet": stderr[:200],
            })

        return json.dumps(results, indent=2)

    @function_tool
    async def afl_minimize_crash(
        ctx: RunContextWrapper,
        binary_path: str,
        crash_file: str,
        output_file: str = "/tmp/min_crash",
        binary_args: str = "@@",
    ) -> str:
        """Minimize a crashing input using afl-tmin.

        Args:
            binary_path: Path to the target binary
            crash_file: Path to the crash input file
            output_file: Where to write minimized crash
            binary_args: Binary arguments (@@ = input file)
        """
        if not shutil.which("afl-tmin"):
            return "afl-tmin not found. Install AFL++."

        if not Path(crash_file).exists():
            return f"Crash file not found: {crash_file}"

        cmd = [
            "afl-tmin",
            "-i", crash_file,
            "-o", output_file,
            "--",
            binary_path,
        ]
        cmd.extend(binary_args.replace("@@", "@@").split())

        stdout, stderr, rc = _run(cmd, timeout=120)
        if rc == 0:
            size_before = Path(crash_file).stat().st_size
            size_after = Path(output_file).stat().st_size if Path(output_file).exists() else "?"
            return (
                f"Minimization complete.\n"
                f"  Before: {size_before} bytes\n"
                f"  After:  {size_after} bytes\n"
                f"  Saved:  {output_file}"
            )
        return f"afl-tmin failed (rc={rc}):\n{stderr[:400]}"

    @function_tool
    async def generate_boofuzz_script(
        ctx: RunContextWrapper,
        host: str,
        port: int,
        protocol: str = "tcp",
        request_type: str = "http",
        output_file: str = "",
    ) -> str:
        """Generate a boofuzz script for network protocol fuzzing.

        Args:
            host: Target host IP or hostname
            port: Target port
            protocol: Transport protocol — "tcp" or "udp"
            request_type: Protocol to fuzz:
                - "http": HTTP GET request fuzzer
                - "ftp": FTP command fuzzer
                - "smtp": SMTP command fuzzer
                - "custom": Generic TCP/UDP fuzzer skeleton
            output_file: Optional path to save the script
        """
        connection_map = {
            "tcp": f"TCPSocketConnection('{host}', {port})",
            "udp": f"UDPSocketConnection('{host}', {port})",
        }
        conn = connection_map.get(protocol.lower(), f"TCPSocketConnection('{host}', {port})")

        templates: dict[str, str] = {
            "http": f'''#!/usr/bin/env python3
# boofuzz HTTP fuzzer
# Install: pip install boofuzz
# Run:     python3 boofuzz_http.py

from boofuzz import *

def main():
    session = Session(
        target=Target(connection={conn}),
        sleep_time=0.5,
        restart_sleep_time=5,
    )

    s_initialize("HTTP GET")

    # Method
    s_string("GET", fuzzable=False)
    s_delim(" ", fuzzable=False)

    # Path — fuzz this
    s_string("/", fuzzable=True)
    s_string("index.php", fuzzable=True)

    s_delim(" ", fuzzable=False)
    s_string("HTTP/1.1", fuzzable=False)
    s_static("\\r\\n")

    # Host header
    s_string("Host", fuzzable=False)
    s_static(": ")
    s_string("{host}", fuzzable=True)  # fuzz host header
    s_static("\\r\\n")

    # User-Agent — fuzz this
    s_string("User-Agent", fuzzable=False)
    s_static(": ")
    s_string("Mozilla/5.0", fuzzable=True)
    s_static("\\r\\n")

    # Content-Length header fuzzing
    s_string("Content-Length", fuzzable=False)
    s_static(": ")
    s_string("0", fuzzable=True)
    s_static("\\r\\n\\r\\n")

    session.connect(s_get("HTTP GET"))
    session.fuzz()

if __name__ == "__main__":
    main()
''',

            "ftp": f'''#!/usr/bin/env python3
# boofuzz FTP command fuzzer

from boofuzz import *

def main():
    session = Session(
        target=Target(connection={conn}),
        sleep_time=1,
    )

    # USER command
    s_initialize("USER")
    s_string("USER", fuzzable=False)
    s_delim(" ")
    s_string("anonymous", fuzzable=True)
    s_static("\\r\\n")

    # PASS command
    s_initialize("PASS")
    s_string("PASS", fuzzable=False)
    s_delim(" ")
    s_string("anonymous@", fuzzable=True)
    s_static("\\r\\n")

    # RETR command (after login)
    s_initialize("RETR")
    s_string("RETR", fuzzable=False)
    s_delim(" ")
    s_string("filename.txt", fuzzable=True)  # path traversal, long strings
    s_static("\\r\\n")

    session.connect(s_get("USER"))
    session.connect(s_get("USER"), s_get("PASS"))
    session.connect(s_get("PASS"), s_get("RETR"))
    session.fuzz()

if __name__ == "__main__":
    main()
''',

            "smtp": f'''#!/usr/bin/env python3
# boofuzz SMTP command fuzzer

from boofuzz import *

def main():
    session = Session(
        target=Target(connection={conn}),
        sleep_time=1,
    )

    s_initialize("EHLO")
    s_string("EHLO", fuzzable=False)
    s_delim(" ")
    s_string("localhost", fuzzable=True)
    s_static("\\r\\n")

    s_initialize("MAIL FROM")
    s_string("MAIL FROM:", fuzzable=False)
    s_string("<test@test.com>", fuzzable=True)
    s_static("\\r\\n")

    s_initialize("RCPT TO")
    s_string("RCPT TO:", fuzzable=False)
    s_string("<victim@target.com>", fuzzable=True)
    s_static("\\r\\n")

    session.connect(s_get("EHLO"))
    session.connect(s_get("EHLO"), s_get("MAIL FROM"))
    session.connect(s_get("MAIL FROM"), s_get("RCPT TO"))
    session.fuzz()

if __name__ == "__main__":
    main()
''',

            "custom": f'''#!/usr/bin/env python3
# boofuzz generic TCP/UDP fuzzer skeleton

from boofuzz import *

def main():
    session = Session(
        target=Target(connection={conn}),
        sleep_time=0.5,
        # Optionally restart target on crash:
        # restart_callbacks=[some_restart_function],
    )

    # Define your protocol message here
    s_initialize("PACKET")

    # Static header
    s_bytes(b"\\x00\\x01", fuzzable=False)  # magic bytes

    # Fuzzable length field
    s_size("payload", length=2, endian=">", fuzzable=True)

    with s_block("payload"):
        # Fuzz the data field
        s_string("data", fuzzable=True)
        s_static(b"\\x00")  # null terminator

    # Monitor for crashes:
    session.connect(s_get("PACKET"))
    session.fuzz()

if __name__ == "__main__":
    main()
''',
        }

        script = templates.get(request_type.lower())
        if not script:
            return f"Unknown request type: {request_type}\nAvailable: {', '.join(templates.keys())}"

        if output_file:
            p = Path(output_file) if output_file.startswith("/") else Path(f"/workspace/{output_file}")
            p.write_text(script, encoding="utf-8")
            p.chmod(0o755)
            return f"Script saved to {p}\n\nInstall boofuzz: pip install boofuzz\nRun: python3 {p}\n\n---\n{script}"

        return script

    @function_tool
    async def create_corpus(
        ctx: RunContextWrapper,
        corpus_dir: str,
        file_type: str = "text",
        sample_count: int = 10,
    ) -> str:
        """Create a seed corpus directory for fuzzing.

        Args:
            corpus_dir: Directory to create corpus in
            file_type: Type of seeds to generate:
                - "text": Simple text inputs
                - "json": JSON structure variations
                - "binary": Binary format seeds
                - "http": HTTP request seeds
                - "xml": XML document seeds
            sample_count: Number of seed files to create
        """
        cdir = Path(corpus_dir)
        cdir.mkdir(parents=True, exist_ok=True)

        generators: dict[str, list[bytes]] = {
            "text": [
                b"", b"A", b"A" * 100, b"A" * 1000,
                b"Hello World", b"test\ntest",
                b"../../etc/passwd", b"' OR 1=1 --",
                b"<script>alert(1)</script>", b"{{7*7}}",
                b"\x00" * 10, b"\xff" * 10,
            ],
            "json": [
                b"{}", b"[]", b"null", b"true",
                b'{"key": "value"}',
                b'{"key": null, "arr": [1, 2, 3]}',
                b'{"key": "' + b"A" * 1000 + b'"}',
                b'{"__proto__": {"polluted": true}}',
                b'[{"id": 1}]',
                b"{}}}}{{{",
            ],
            "binary": [
                b"\x00", b"\xff", b"\x00" * 4, b"\xff" * 4,
                b"\x41\x42\x43\x44",
                b"\xde\xad\xbe\xef",
                b"\x7fELF" + b"\x00" * 8,
                b"MZ" + b"\x00" * 6,
                b"\x89PNG\r\n\x1a\n" + b"\x00" * 4,
                b"PK\x03\x04" + b"\x00" * 8,
            ],
            "http": [
                b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
                b"GET /../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
                b"GET / HTTP/1.1\r\n" + b"X-Header: " + b"A" * 8192 + b"\r\n\r\n",
                b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n",
                b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                b"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest",
                b"DELETE / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                b"GET /?a=1&b=2 HTTP/1.1\r\nHost: localhost\r\n\r\n",
                b"GET / HTTP/999.9\r\nHost: localhost\r\n\r\n",
            ],
            "xml": [
                b"<root/>", b"<root></root>", b"<root><child/></root>",
                b"<?xml version='1.0'?><root/>",
                b"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                b"<" + b"A" * 1000 + b"/>",
                b"<root>" + b"<a>" * 100 + b"</a>" * 100 + b"</root>",
                b"<!-- comment --><root/>",
                b"<root xmlns='http://evil.com'/>",
                b"<root attr='" + b"A" * 500 + b"'/>",
            ],
        }

        seeds = generators.get(file_type.lower(), generators["text"])
        created = []
        for i, data in enumerate(seeds[:sample_count]):
            fname = cdir / f"seed_{i:03d}"
            fname.write_bytes(data)
            created.append(str(fname))

        return (
            f"Corpus created in {corpus_dir}\n"
            f"Files created: {len(created)}\n"
            f"Type: {file_type}\n\n"
            f"Files:\n" + "\n".join(f"  {c}" for c in created)
        )

else:
    def afl_fuzz_start(*a, **kw): raise ImportError("agents SDK not installed")
    def afl_fuzz_status(*a, **kw): raise ImportError("agents SDK not installed")
    def afl_triage_crashes(*a, **kw): raise ImportError("agents SDK not installed")
    def afl_minimize_crash(*a, **kw): raise ImportError("agents SDK not installed")
    def generate_boofuzz_script(*a, **kw): raise ImportError("agents SDK not installed")
    def create_corpus(*a, **kw): raise ImportError("agents SDK not installed")
