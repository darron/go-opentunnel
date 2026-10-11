#!/usr/bin/env python3
"""Opt-in live auth-proxy checks. Creates and deletes temporary public tunnels."""

import concurrent.futures
import http.client
import http.cookiejar
import json
import os
import re
import select
import signal
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def passed(message):
    print("PASS: " + message, flush=True)


def main():
    cli = Path("bin/otgo").resolve()
    if not cli.is_file():
        raise RuntimeError("run make build first")
    work = Path(tempfile.mkdtemp(prefix="otgo-auth-smoke-"))
    os.chmod(work, 0o700)
    helper = work / "backend"
    subprocess.run(["go", "build", "-o", str(helper), "./scripts/auth-smoke"], check=True)
    processes, profiles, logs = [], [], []
    plain = urllib.request.build_opener(NoRedirect())
    jar = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())

    def flags(profile, auth=True):
        result = ["--profile", profile, "--data-dir", str(work / "tunnels")]
        if auth:
            result += ["--auth-config", str(work / "config" / profile / "auth.json"),
                       "--token-file", str(work / "tokens" / profile / "tokens.json")]
        return result

    def command(words, profile="first", auth=True, success=True, extra=()):
        result = subprocess.run([str(cli), *words, *flags(profile, auth), *extra],
                                capture_output=True, text=True, timeout=330)
        if success and result.returncode:
            raise RuntimeError("CLI command failed: " + " ".join(words) + ": " + result.stderr)
        return result

    def value(words, profile="first", auth=True, extra=()):
        return json.loads(command(words, profile, auth, extra=(*extra, "--json")).stdout)

    def spawn(args, name):
        log = (work / (name + ".err")).open("w")
        os.chmod(log.name, 0o600)
        logs.append(log)
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=log,
                                   stdin=subprocess.PIPE, text=True, bufsize=1)
        processes.append(process)
        return process

    def line(process, timeout=30):
        if not select.select([process.stdout], [], [], timeout)[0]:
            raise RuntimeError("process did not emit expected readiness output")
        output = process.stdout.readline().strip()
        if not output:
            raise RuntimeError("process exited before readiness")
        return output

    def stop(process):
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            process.wait(timeout=10)
        return process.returncode

    def fetch(address, path="/", method="GET", data=None, headers=None, agent=plain):
        request = urllib.request.Request(address + path, data=data, method=method, headers=headers or {})
        try:
            response = agent.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read()

    def proxy(profile, name):
        process = spawn([str(cli), "proxy", *flags(profile), "--json"], name)
        line(process, 60)
        return process

    def csrf(origin, path="/__otgo/login"):
        status, _, body = fetch(origin, path, agent=browser)
        assert status in (200, 401)
        return re.search(rb'name="csrf" value="([^"]+)"', body).group(1).decode()

    try:
        backend = spawn([str(helper)], "backend")
        upstream = line(backend)
        profiles.append("first")
        setup = value(["auth", "init"], extra=("--upstream", upstream))
        password = setup["password"]
        hostname = setup["Hostname"]
        origin = "https://" + hostname
        running = proxy("first", "proxy")
        for _ in range(100):
            try:
                if fetch(origin)[0] == 401:
                    break
            except OSError:
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError("public proxy did not become ready")
        before = fetch(upstream, "/stats")[2]
        for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"]:
            for path in ["/", "/mcp", "/static/app.js", "/health", "/.well-known/oauth-protected-resource", "/%6dcp", "//mcp"]:
                assert fetch(origin, path, method)[0] >= 400, (method, path)
        assert fetch(origin, "/__otgo/unknown")[0] == 404
        assert fetch(upstream, "/stats")[2] == before
        passed("every anonymous method/route denied; zero backend requests, including MCP and discovery")
        token = value(["auth", "token", "create"], extra=("--ttl", "1h"))
        bearer = {"Authorization": "Bearer " + token["token"]}
        assert fetch(origin, "/mcp", "POST", b"{}", bearer)[0] == 200
        assert value(["get"], auth=False)["hostname"] == hostname
        assert token["id"] in command(["auth", "token", "list"]).stdout
        duplicate = command(["proxy"], success=False, extra=("--timeout", "3s"))
        assert duplicate.returncode != 0 and "lock" in duplicate.stderr
        passed("machine MCP access, hostname lookup/token minting while running, duplicate-profile refusal")
        assert fetch(origin, "/__otgo/login", "POST", b"password=x", {"Origin": "https://evil.test"})[0] == 403
        form = urllib.parse.urlencode({"password": "wrong", "csrf": csrf(origin)}).encode()
        headers = {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}
        assert fetch(origin, "/__otgo/login", "POST", form, headers, browser)[0] == 401
        form = urllib.parse.urlencode({"password": password, "csrf": csrf(origin)}).encode()
        status, response_headers, _ = fetch(origin, "/__otgo/login", "POST", form, headers, browser)
        assert status == 303
        session = next(cookie for cookie in jar if cookie.name == "__Host-otgo-session")
        assert session.secure and "HttpOnly" in response_headers.get("Set-Cookie")
        assert fetch(origin, "/mcp", "POST", b"{}", {"Origin": origin}, browser)[0] == 200
        assert fetch(origin, "/mcp", "POST", b"{}", agent=browser)[0] == 403
        assert fetch(origin, "/", headers={"Authorization": "Bearer otgo_invalid"}, agent=browser)[0] == 401
        passed("password denial/login, secure cookie, browser CSRF/origin checks, invalid token cannot fall back")
        headers = {"X-Otgo-Token": token["token"], "Authorization": "Bearer backend-auth",
                   "Origin": origin, "Referer": origin + "/page", "X-Forwarded-For": "forged"}
        status, response_headers, body = fetch(origin, "/headers?q=1", headers=headers, agent=browser)
        seen = json.loads(body)
        assert status == 200 and seen["Host"] == urllib.parse.urlsplit(upstream).netloc
        assert seen["Authorization"] == "Bearer backend-auth" and seen["Token"] == "" and seen["Forwarded"] == ""
        assert "__Host-otgo-" not in seen["Cookie"]
        assert seen["Origin"] == upstream and seen["Referer"] == upstream + "/page" and seen["Query"] == "q=1"
        assert response_headers.get_all("Set-Cookie") == ["backend=ok; Path=/"]
        status, response_headers, _ = fetch(origin, "/redirect", headers=bearer)
        assert status == 302 and response_headers["Location"] == origin + "/next?q=1"
        passed("backend credentials preserved; gate credentials/spoofed identity headers stripped; redirects/cookies adapted")
        status, response_headers, body = fetch(origin, "/cache", headers=bearer)
        assert status == 200 and body == b"protected-cache-canary\n"
        assert response_headers["Cache-Control"] == "private, no-store"
        assert response_headers["Referrer-Policy"] == "same-origin"
        assert response_headers["Pragma"] == "no-cache" and response_headers["Expires"] == "0"
        assert response_headers.get("CDN-Cache-Control") is None
        assert response_headers.get("X-Accel-Expires") is None
        assert fetch(origin, "/cache")[0] == 401
        passed("public backend cache policy overridden; anonymous cache endpoint denied")
        for site, mode, dest in [("same-site", "no-cors", "script"), ("cross-site", "no-cors", "image"), ("same-site", "navigate", "iframe")]:
            assert fetch(origin, "/", headers={"Sec-Fetch-Site": site, "Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest}, agent=browser)[0] == 403
        assert fetch(origin, "/", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}, agent=browser)[0] == 200
        passed("browser foreign subresources denied; top-level navigation preserved")
        payload = b"x" * (2 << 20)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: fetch(origin, "/upload", "POST", payload, bearer), range(8)))
        assert all(status == 200 and body == payload for status, _, body in results)
        passed("eight simultaneous 2 MiB uploads round-trip intact")
        stream = plain.open(urllib.request.Request(origin + "/sse", headers=bearer), timeout=15)
        assert stream.readline() == b"data: tick\n"
        websocket = spawn([str(helper), "--probe", "wss://" + hostname + "/ws"], "websocket")
        websocket.stdin.write(token["token"] + "\n")
        websocket.stdin.flush()
        assert line(websocket) == "ready"
        started = time.monotonic()
        command(["auth", "token", "revoke"], extra=("--id", token["id"]))
        assert line(websocket, 3) == "revoked" and websocket.wait(timeout=3) == 0
        try:
            while stream.read(1024):
                pass
        except (OSError, http.client.IncompleteRead):
            pass
        finally:
            stream.close()
        elapsed = time.monotonic() - started
        assert elapsed < 2, "live revocation exceeded two seconds"
        assert fetch(origin, "/mcp", "POST", b"{}", bearer)[0] == 401
        passed(f"SSE/WSS streaming and live revocation closed both streams in {elapsed:.3f}s")
        token = value(["auth", "token", "create"])
        bearer = {"Authorization": "Bearer " + token["token"]}
        token_path = work / "tokens" / "first" / "tokens.json"
        registry = token_path.read_bytes()
        token_path.write_bytes(b"corrupt")
        assert fetch(origin, headers=bearer)[0] == 401
        token_path.write_bytes(registry)
        passed("corrupt registry fails closed")
        assert stop(running) == 0
        running = proxy("first", "proxy-restarted")
        assert fetch(origin, agent=browser)[0] == 401
        assert fetch(origin, headers=bearer)[0] == 200
        assert value(["get"], auth=False)["hostname"] == hostname
        passed("restart retains hostname, backend and machine tokens; browser sessions are invalidated")
        form = urllib.parse.urlencode({"password": password, "csrf": csrf(origin)}).encode()
        assert fetch(origin, "/__otgo/login", "POST", form, {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}, browser)[0] == 303
        form = urllib.parse.urlencode({"csrf": csrf(origin, "/__otgo/logout")}).encode()
        assert fetch(origin, "/__otgo/logout", "POST", form, {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}, browser)[0] == 303
        assert fetch(origin, agent=browser)[0] == 401
        backend2 = spawn([str(helper)], "backend-second")
        upstream2 = line(backend2)
        profiles.append("second")
        setup2 = value(["auth", "init"], "second", extra=("--upstream", upstream2))
        proxy("second", "proxy-second")
        token2 = value(["auth", "token", "create"], "second")
        origin2 = "https://" + setup2["Hostname"]
        assert origin2 != origin and upstream2 != upstream
        assert fetch(origin2, "/headers", headers={"Authorization": "Bearer " + token2["token"]})[0] == 200
        assert fetch(origin2, headers=bearer)[0] == 401
        assert fetch(origin, headers={"Authorization": "Bearer " + token2["token"]})[0] == 401
        passed("logout and simultaneous isolated profiles with different backends; cross-profile credentials denied")
    finally:
        failures = []
        for process in reversed(processes):
            try:
                code = stop(process)
                if code != 0:
                    failures.append("owned process exited unsuccessfully: " + str(code))
            except Exception as error:
                failures.append(type(error).__name__ + " stopping owned process")
        for profile in profiles:
            try:
                folder = work / "tunnels" / profile
                metadata = folder / "tunnel.json"
                if not metadata.exists():
                    metadata = folder / "pending.json"
                identity = json.loads(metadata.read_text()) if metadata.exists() else None
                credential = (folder / "token").read_text().strip() if identity else None
                command(["auth", "reset"], profile)
                command(["remove"], profile, auth=False)
                assert value(["get"], profile, auth=False) is None
                if identity:
                    result = subprocess.run([str(helper), "--inspect"], input=json.dumps({"ID": identity["id"], "Token": credential}), capture_output=True, text=True, timeout=25)
                    assert result.returncode == 0, "remote removal was not confirmed"
            except Exception as error:
                failures.append(profile + ": " + str(error))
        for log in logs:
            log.close()
        if failures:
            raise RuntimeError("cleanup needs attention in " + str(work) + ": " + "; ".join(failures))
        shutil.rmtree(work)
        passed("all test processes stopped; local credentials removed; remote removals confirmed by API 404")


if __name__ == "__main__":
    main()
