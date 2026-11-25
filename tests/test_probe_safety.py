"""
라이브 점검 안전장치 회귀 테스트 (네트워크 없이 돌아감)
  python -m unittest tests.test_probe_safety
"""
import os, subprocess, sys, tempfile, unittest
from types import SimpleNamespace
from unittest import mock

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
import probe
import vibescan

ENV = "VITE_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\n"


def run_main(argv):
    """vibescan.main()을 돌리고 probe.run 호출 여부를 돌려준다."""
    with mock.patch.object(sys, "argv", ["vibescan.py"] + argv), \
            mock.patch.object(probe, "run", return_value=[]) as run:
        vibescan.main()
    return run


class ProbeOptInTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with open(os.path.join(self.tmp.name, ".env"), "w") as fh:
            fh.write(ENV)

    def test_env_without_flag_sends_no_live_request(self):
        run_main([self.tmp.name]).assert_not_called()

    def test_url_and_key_without_flag_send_no_live_request(self):
        run_main(["--url", "https://x.supabase.co", "--key", "k"]).assert_not_called()

    def test_flag_runs_live(self):
        run_main([self.tmp.name, "--probe"]).assert_called_once()

    def test_no_live_beats_flag(self):
        run_main([self.tmp.name, "--probe", "--no-live"]).assert_not_called()

    def test_run_all_defaults_to_no_live(self):
        with mock.patch.object(probe, "run", return_value=[]) as run:
            vibescan.run_all(self.tmp.name)
        run.assert_not_called()


class CaptureOptInTest(unittest.TestCase):
    def test_capture_is_off_by_default(self):
        # 다른 테스트의 상태에 기대지 않도록 새 프로세스에서 확인
        out = subprocess.check_output(
            [sys.executable, "-c", "import probe; print(probe.CAPTURE_ENABLED)"],
            cwd=ROOT, text=True)
        self.assertEqual(out.strip(), "False")

    def test_capture_writes_nothing_by_default(self):
        resp = SimpleNamespace(text="secret row", url="u", status_code=200, headers={})
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(probe, "CAPTURE_DIR", os.path.join(d, "fx")):
            probe.capture("table_users", resp)
            self.assertFalse(os.path.exists(os.path.join(d, "fx")))


if __name__ == "__main__":
    unittest.main()
