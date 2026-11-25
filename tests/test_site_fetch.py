"""
사이트 주소 진단: HTML 안에 스크립트만 있는 페이지도 점검한다 (네트워크 없이 돌아감)
  python -m unittest tests.test_site_fetch
"""
import io, os, sys, tempfile, unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scanner
import server

URL = "https://app.example/"


def fake_get(pages):
    """주소별 응답을 돌려주는 safe_get 대역. 없는 주소는 404."""
    def get(url, _limit):
        body = pages.get(url)
        status = 200 if body is not None else 404
        return SimpleNamespace(status_code=status), url, io.BytesIO((body or "").encode())
    return get


def fetch(pages):
    d = tempfile.TemporaryDirectory()
    with mock.patch.object(server, "safe_get", fake_get(pages)):
        host = server.fetch_site(URL, d.name)
    return d, host


class InlineScriptTest(unittest.TestCase):
    def test_inline_script_page_is_accepted(self):
        d, host = fetch({URL: "<html><script>var a = 1;</script></html>"})
        self.addCleanup(d.cleanup)
        self.assertEqual(host, "app.example")
        self.assertTrue(os.path.exists(os.path.join(d.name, "index.html")))

    def test_inline_secret_is_found_by_the_scanner(self):
        key = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
        d, _ = fetch({URL: f'<html><script>var k = "{key}";</script></html>'})
        self.addCleanup(d.cleanup)
        crit = [f for f in scanner.run(d.name) if f["severity"] == "CRITICAL"]
        self.assertTrue(crit, "HTML 안의 비밀 키를 찾아야 함")

    def test_external_bundle_still_downloaded(self):
        d, _ = fetch({URL: '<script src="/assets/app.js"></script>',
                      "https://app.example/assets/app.js": "var a = 1;"})
        self.addCleanup(d.cleanup)
        self.assertEqual(os.listdir(os.path.join(d.name, "assets")), ["assets_app.js"])


class NoCodeTest(unittest.TestCase):
    def assert_no_code(self, page):
        with self.assertRaises(server.ScanError) as cm:
            fetch({URL: page})
        self.assertIn("점검할 코드", str(cm.exception))

    def test_plain_html_is_rejected(self):
        self.assert_no_code("<html><body>hello</body></html>")

    def test_empty_script_is_rejected(self):
        self.assert_no_code("<html><script>  \n </script></html>")

    def test_json_data_block_is_not_code(self):
        self.assert_no_code('<script type="application/ld+json">{"a": 1}</script>')

    def test_other_site_script_only_is_rejected(self):
        self.assert_no_code('<script src="https://cdn.other.example/x.js"></script>')


if __name__ == "__main__":
    unittest.main()
