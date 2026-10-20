#!/usr/bin/env python3
"""Test coder/websocket against the pinned OpenTunnel v0.5.4 server codec.

Rust and Cargo are test-only tools. No upstream source or build output is kept
in the checkout. Run from any directory with python3 scripts/upstream_compat.py.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request

REVISION = "8e6f7ed6da49d524b46ff27d6704879725c40300"
SHA256 = "c49e727c9cc9b8d8085d32eb70e99004892a4e7f77031fc803ff881a78b988d1"
ROOT = Path(__file__).resolve().parent.parent


def main():
    with tempfile.TemporaryDirectory(prefix="otgo-upstream-compat-") as temporary:
        project = Path(temporary)
        shutil.copytree(ROOT / "scripts/upstream-compat", project, dirs_exist_ok=True)
        url = f"https://raw.githubusercontent.com/anomalyco/opentunnel/{REVISION}/crates/opentunnel-server/src/websocket.rs"
        with urllib.request.urlopen(url, timeout=30) as response:
            source = response.read(256 * 1024)
        if hashlib.sha256(source).hexdigest() != SHA256:
            raise RuntimeError("upstream codec checksum mismatch")
        (project / "websocket.rs").write_bytes(source)
        subprocess.run(["cargo", "build", "--locked", "--manifest-path", str(project / "Cargo.toml")], check=True)
        env = dict(os.environ, OTGO_UPSTREAM_WEBSOCKET_FIXTURE=str(project / "target/debug/otgo-upstream-codec"))
        subprocess.run(["go", "test", "-race", "-count=1", "-run", "^TestUpstreamWebSocketCodec$", "."], cwd=ROOT, env=env, check=True)
        print(f"PASS: OpenTunnel v0.5.4 codec {REVISION}, SHA-256 {SHA256}")


if __name__ == "__main__":
    main()
