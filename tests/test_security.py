"""
보안 수정 회귀 테스트 (네트워크 없이 돌아감)
  python -m unittest discover -s tests
"""
import http.server, io, os, socket, sys, tempfile, threading, unittest, zipfile
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import probe
import scanner
import server


def fake_dns(*ips):
    return lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]


class ResolvePublicTest(unittest.TestCase):
    def test_rejects_loopback_and_private(self):
        for ip in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1"):
            with mock.patch("socket.getaddrinfo", fake_dns(ip)):
                with self.assertRaises(server.ScanError):
                    server.resolve_public("https://evil.example/")

    def test_rejects_ipv4_mapped_loopback(self):
        with mock.patch("socket.getaddrinfo", fake_dns("::ffff:127.0.0.1")):
            with self.assertRaises(server.ScanError):
                server.resolve_public("https://evil.example/")

    def test_rejects_if_any_address_private(self):
        with mock.patch("socket.getaddrinfo", fake_dns("93.184.215.14", "127.0.0.1")):
            with self.assertRaises(server.ScanError):
                server.resolve_public("https://mixed.example/")

    def test_rejects_non_web_ports(self):
        with self.assertRaises(server.ScanError):
            server.resolve_public("http://example.com:6379/")

    def test_returns_validated_ip(self):
        with mock.patch("socket.getaddrinfo", fake_dns("93.184.215.14")):
            self.assertEqual(server.resolve_public("https://ok.example/"), "93.184.215.14")


class PinningTest(unittest.TestCase):
    """검증한 IP로만 연결되고, Host 헤더는 원래 호스트명을 유지하는지."""

    def test_connects_to_pinned_ip_with_original_host(self):
        seen = {}

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen["host"] = self.headers["Host"]
                self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        try:
            # 이 호스트명은 DNS에 없음 → 연결이 됐다면 고정 IP로 간 것
            sess = server.requests.Session()
            sess.mount("http://", server._PinnedAdapter("127.0.0.1"))
            r = sess.get(f"http://pinned-host.invalid:{port}/", timeout=5)
            self.assertEqual(r.text, "ok")
            self.assertEqual(seen["host"], f"pinned-host.invalid:{port}")
        finally:
            srv.shutdown()

    def test_dns_change_after_check_is_ignored(self):
        """검증 때는 공개 IP, 연결 때는 내부 IP를 돌려주는 DNS여도 검증한 IP로 연결."""
        answers = iter([fake_dns("93.184.215.14"), fake_dns("127.0.0.1")])
        calls = []

        def flip(*a, **k):
            return next(answers)(*a, **k)

        def fake_create_connection(addr, *a, **k):
            calls.append(addr[0])
            raise OSError("stop here")

        with mock.patch("socket.getaddrinfo", flip), \
             mock.patch("urllib3.util.connection.create_connection", fake_create_connection):
            with self.assertRaises(Exception):
                server.pinned_get("http://rebind.example/")
        self.assertEqual(calls, ["93.184.215.14"])


class ClientIpTest(unittest.TestCase):
    def req(self, xff):
        return SimpleNamespace(headers={"x-forwarded-for": xff} if xff else {},
                               client=SimpleNamespace(host="10.1.1.1"))

    def test_spoofed_first_value_is_ignored(self):
        # Render 실측: [클라이언트가 넣은 값..., 실제 클라이언트, 프록시, 내부 LB]
        xff = "6.6.6.6, 203.0.113.7, 104.23.1.1, 10.27.1.1"
        with mock.patch.object(server, "TRUSTED_PROXY_HOPS", 3):
            self.assertEqual(server.client_ip(self.req(xff)), "203.0.113.7")

    def test_no_header_uses_socket_peer(self):
        self.assertEqual(server.client_ip(self.req("")), "10.1.1.1")


class SafeExtractTest(unittest.TestCase):
    def make_zip(self, entries):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in entries:
                z.writestr(name, data)
        buf.seek(0)
        return zipfile.ZipFile(buf)

    def test_zip_slip_entry_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "out"); os.makedirs(dest)
            server.safe_extract(self.make_zip([("../evil.txt", "x"), ("ok/a.txt", "y")]), dest)
            self.assertFalse(os.path.exists(os.path.join(d, "evil.txt")))
            self.assertTrue(os.path.exists(os.path.join(dest, "ok", "a.txt")))

    def test_bomb_stops_on_real_bytes(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(server, "MAX_UNZIP_BYTES", 1000):
            with self.assertRaises(server.ScanError):
                server.safe_extract(self.make_zip([("big.txt", "0" * 5000)]), d)

    def test_too_many_entries(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(server, "MAX_ZIP_ENTRIES", 2):
            with self.assertRaises(server.ScanError):
                server.safe_extract(self.make_zip([(f"{i}.txt", "x") for i in range(3)]), d)


class TableExtractionTest(unittest.TestCase):
    def test_from_calls_and_migrations(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "app.ts"), "w").write(
                "supabase.from('todos').select('*'); supabase.storage.from('avatars').upload(x)")
            open(os.path.join(d, "init.sql"), "w").write(
                "create table public.profiles (id uuid); create table auth.secret (x int);")
            self.assertEqual(probe.extract_tables(d), ["profiles", "todos"])


class MigrationCheckTest(unittest.TestCase):
    def run_on(self, files):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "supabase", "migrations"))
            for name, text in files.items():
                open(os.path.join(d, "supabase", "migrations", name), "w").write(text)
            return [f["rule"] for f in scanner.run(d) if f["rule"].startswith("마이그레이션")]

    def test_table_without_rls(self):
        rules = self.run_on({"1.sql": "create table todos (id int);"})
        self.assertIn("마이그레이션: RLS 꺼진 테이블(확인 필요)", rules)

    def test_table_with_rls_and_owner_policy(self):
        rules = self.run_on({"1.sql": "create table todos (id int, user_id uuid);\n"
                                      "alter table todos enable row level security;\n"
                                      "create policy own on todos for select using (auth.uid() = user_id);"})
        self.assertEqual(rules, [])

    def test_permissive_policy(self):
        rules = self.run_on({"1.sql": "create table posts (id int);\n"
                                      "alter table public.posts enable row level security;\n"
                                      "create policy \"anyone\" on public.posts for select using (true);"})
        self.assertEqual(rules, ["마이그레이션: 누구에게나 열린 RLS 정책(확인 필요)"])

    def test_non_supabase_project_not_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "0000.sql"), "w").write("create table todos (id int);")
            rules = [f["rule"] for f in scanner.run(d) if f["rule"].startswith("마이그레이션")]
            self.assertEqual(rules, [])


if __name__ == "__main__":
    unittest.main()
