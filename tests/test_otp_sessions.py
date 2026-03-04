"""Test OTP detection, submission, and session persistence."""
import asyncio
import json
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler


otp_state = {"sent": False, "verified": False}


class MockLoginHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'<html><body><a href="/login">Log in</a><a href="/dashboard">Dashboard</a></body></html>')
        elif self.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("x-csrf-token", "csrf123")
            self.end_headers()
            self.wfile.write(
                b'<html><body><form action="/api/auth/login" method="POST">'
                b'<input name="email"/><input type="password" name="password"/>'
                b"<button>Sign in</button></form></body></html>"
            )
        elif self.path == "/dashboard":
            cookies = self.headers.get("Cookie", "")
            if "session=" in cookies:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b'<html><body>Welcome dashboard <a href="/logout">Sign out</a></body></html>'
                )
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl).decode()
        ct = self.headers.get("Content-Type", "")

        if self.path == "/api/auth/login":
            if "application/json" in ct:
                try:
                    d = json.loads(body)
                    email = d.get("email", "")
                    pw = d.get("password", "")
                except Exception:
                    email = pw = ""
            else:
                from urllib.parse import parse_qs

                f = parse_qs(body)
                email = f.get("email", [""])[0]
                pw = f.get("password", [""])[0]

            if email == "test@test.com" and pw == "hunter2":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "session=sess-abc123; Path=/")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "success": True,
                            "access_token": "eyJhbGciOiJIUzI1NiJ9.test.sig",
                        }
                    ).encode()
                )
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {"success": False, "error": "Invalid credentials"}
                    ).encode()
                )

        elif self.path == "/api/auth/login-otp":
            if "application/json" in ct:
                try:
                    d = json.loads(body)
                    email = d.get("email", "")
                    pw = d.get("password", "")
                except Exception:
                    email = pw = ""
            else:
                email = pw = ""

            if email == "otp@test.com" and pw == "pass123":
                otp_state["sent"] = True
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "success": False,
                            "requires_verification": True,
                            "message": "We sent a verification code to your email. Please check your inbox.",
                            "verify_token": "vt-12345",
                        }
                    ).encode()
                )
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {"success": False, "error": "Invalid credentials"}
                    ).encode()
                )

        elif self.path == "/api/auth/verify":
            if "application/json" in ct:
                try:
                    d = json.loads(body)
                    code = d.get("code", "")
                    vt = d.get("verify_token", "")
                except Exception:
                    code = vt = ""
            else:
                code = vt = ""

            if code == "123456" and vt == "vt-12345":
                otp_state["verified"] = True
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "session=otp-session-789; Path=/")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "success": True,
                            "access_token": "eyJhbGciOiJIUzI1NiJ9.otp.verified",
                        }
                    ).encode()
                )
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps({"success": False, "error": "Invalid code"}).encode()
                )
        else:
            self.send_response(404)
            self.end_headers()


def main():
    server = HTTPServer(("127.0.0.1", 0), MockLoginHandler)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)
    print(f"Mock server on {base_url}")

    async def run_tests():
        p = f = 0
        errs = []

        def check(name, cond, detail=""):
            nonlocal p, f
            if cond:
                p += 1
                print(f"  PASS {name}")
            else:
                f += 1
                errs.append(name)
                print(f"  FAIL {name}: {detail}")

        from beatrix.core.auto_login import (
            AutoLoginEngine,
            LoginResult,
            clear_session,
            list_sessions,
            load_session,
            perform_auto_login,
            save_session,
        )
        from beatrix.core.auth_config import AuthCredentials

        # ── Test 1: Normal login ──
        print("\n-- Test 1: Normal login --")
        r1 = await AutoLoginEngine(
            target=base_url, username="test@test.com", password="hunter2"
        ).login()
        check("Login succeeds", r1.success, r1.message)
        check("Session cookie", "session" in r1.cookies, str(r1.cookies))
        check("Auth token", r1.token is not None, str(r1.token))

        # ── Test 2: Wrong creds ──
        print("\n-- Test 2: Wrong creds --")
        r2 = await AutoLoginEngine(
            target=base_url, username="test@test.com", password="wrong"
        ).login()
        check("Login fails", not r2.success, r2.message)
        check("Rejection message", "rejected" in r2.message.lower(), r2.message)

        # ── Test 3: OTP detection (non-interactive) ──
        print("\n-- Test 3: OTP detection (non-interactive) --")
        r3 = await AutoLoginEngine(
            target=base_url,
            username="otp@test.com",
            password="pass123",
            login_url=f"{base_url}/api/auth/login-otp",
            login_method="json",
            interactive=False,
        ).login()
        check("Not successful (needs OTP)", not r3.success, r3.message)
        check("OTP required flag set", r3.otp_required, str(r3.otp_required))
        check(
            "Message mentions OTP/2FA",
            "otp" in r3.message.lower() or "2fa" in r3.message.lower(),
            r3.message,
        )

        # ── Test 4: OTP context extraction ──
        print("\n-- Test 4: OTP context --")
        import httpx

        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.post(
                f"{base_url}/api/auth/login-otp",
                json={"email": "otp@test.com", "password": "pass123"},
                headers={"Content-Type": "application/json"},
            )
            engine = AutoLoginEngine(
                target=base_url, username="otp@test.com", password="pass123"
            )
            ctx = engine._detect_otp_response(resp)
            check("OTP context detected", ctx is not None, str(ctx))
            if ctx:
                check(
                    "Verify token extracted",
                    ctx.get("verify_token") == "vt-12345",
                    str(ctx),
                )
                check(
                    "User message present",
                    "verification code" in ctx.get("user_message", "").lower(),
                    str(ctx),
                )

        # ── Test 5: OTP submission ──
        print("\n-- Test 5: OTP submission --")
        async with httpx.AsyncClient(verify=False) as client:
            engine = AutoLoginEngine(
                target=base_url, username="otp@test.com", password="pass123"
            )
            otp_ctx = {
                "verify_token": "vt-12345",
                "verify_token_key": "verify_token",
                "login_url": f"{base_url}/api/auth/login-otp",
                "cookies": {},
            }
            otp_result = await engine._submit_otp(client, "123456", otp_ctx, {})
            check("OTP verification succeeds", otp_result.success, otp_result.message)
            check(
                "Session cookie from OTP",
                "session" in otp_result.cookies,
                str(otp_result.cookies),
            )
            check(
                "Token from OTP",
                otp_result.token is not None,
                str(otp_result.token),
            )

        # ── Test 6: Session persistence ──
        print("\n-- Test 6: Session persistence --")
        test_result = LoginResult(
            success=True,
            cookies={"session": "test-session-123"},
            headers={"Authorization": "Bearer test-token"},
            token="test-token",
            method_used="json",
            login_url=f"{base_url}/api/auth/login",
            message="test",
        )
        path = save_session("test-domain.com", test_result)
        check("Session file created", path.exists(), str(path))

        loaded = load_session("test-domain.com")
        check("Session loaded", loaded is not None and loaded.success, str(loaded))
        if loaded:
            check(
                "Cookies preserved",
                loaded.cookies.get("session") == "test-session-123",
                str(loaded.cookies),
            )
            check("Token preserved", loaded.token == "test-token", str(loaded.token))

        sessions = list_sessions()
        check(
            "Session in list",
            any(s["domain"] == "test-domain.com" for s in sessions),
            str(sessions),
        )

        cleared = clear_session("test-domain.com")
        check("Session cleared", cleared, "")
        check("Session gone after clear", load_session("test-domain.com") is None, "")

        # ── Test 7: Crawler with auth ──
        print("\n-- Test 7: Crawler with auth --")
        c7 = AuthCredentials(
            login_username="test@test.com", login_password="hunter2"
        )
        r7 = await perform_auto_login(c7, target=base_url)
        if r7.success:
            c7.cookies.update(r7.cookies)
            c7.headers.update(r7.headers)
            if r7.token:
                c7.bearer_token = r7.token
        from beatrix.scanners.crawler import TargetCrawler

        cr = await TargetCrawler(max_pages=5, max_depth=1).crawl(base_url, auth=c7)
        check(
            "Found /dashboard (auth-only)",
            any("/dashboard" in u for u in cr.urls),
            str(cr.urls),
        )

        # ── Test 8: Scanner auth injection ──
        print("\n-- Test 8: Scanner auth injection --")
        from beatrix.scanners.base import BaseScanner

        class DummyScanner(BaseScanner):
            name = "t"

            async def scan(self, ctx):
                yield

        s = DummyScanner()
        s.client = httpx.AsyncClient()
        s.apply_auth(c7)
        check(
            "Auth header injected",
            "eyJ" in s.client.headers.get("authorization", ""),
        )
        check(
            "Cookie header injected",
            "session=" in s.client.headers.get("cookie", ""),
        )
        await s.client.aclose()

        total = p + f
        print(f"\nResults: {p}/{total} passed, {f} failed")
        if errs:
            print(f"Failed: {', '.join(errs)}")
        return f == 0

    ok = asyncio.run(run_tests())
    server.shutdown()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
