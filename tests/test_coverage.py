"""
점검 범위와 리포트 정직성 회귀 테스트 (네트워크 없이 돌아감, fastapi 불필요)
  python -m unittest tests.test_coverage

지키려는 것: 문제를 못 찾은 것과 아예 보지 못한 것을 섞지 않는다.
  - 화면 코드(번들)만 받은 진단에서 '서버가 로그인을 확인한다' 같은 잘 된 점을 내지 않는다.
  - 볼 수 없었던 영역은 '확인 못 함'으로 따로 적고, 리포트 첫 문장이 '문제없음'으로 읽히지 않는다.
"""
import json, os, re, subprocess, sys, tempfile, unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
import report
import report_html
import scanner

# supabase-js 라이브러리가 번들에 남기는 모양. 메서드 이름은 빌드 뒤에도 그대로 남는다.
SUPABASE_LIB = ('class GoTrue{async getSession(){return this.s}async getUser(e){return this._getUser(e)}}'
                'const sb=createClient("https://abcdefghijklmnopqrst.supabase.co",'
                '"sb_publishable_AbCdEfGhIjKlMnOpQrStUv12");')
SITE = {"index.html": "<html></html>", "assets/app.js": SUPABASE_LIB}

SERVER_ROUTE = ('export async function POST(req){\n'
                '  const { data: { user } } = await supabase.auth.getUser();\n'
                '  await supabase.from("todos").insert({ title: "a", user_id: user.id });\n'
                '  return supabase.from("todos").select("*").eq("user_id", user.id);\n'
                '}\n')
RLS_SQL = ("create table todos (id int, user_id uuid);\n"
           "alter table todos enable row level security;\n"
           "create policy own on todos for select using (auth.uid() = user_id);")


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def scan(files, kind="repo", live=False):
    """임시 폴더에 파일을 만들어 점검하고 (발견 항목, 점검 범위)를 돌려준다."""
    with tempfile.TemporaryDirectory() as d:
        for rel, text in files.items():
            write(d, rel, text)
        found = scanner.run(d, kind=kind)
        return found, scanner.coverage(found, scanner.FACTS, live=live)


def rules(found):
    return [f["rule"] for f in found]


def status(cov):
    return {r["key"]: r["status"] for r in cov}


class GoodSignalTest(unittest.TestCase):
    """'잘 된 점'은 실제로 확인한 것만."""

    def test_site_bundle_gives_no_good_signal(self):
        found, _ = scan(SITE, kind="site")
        self.assertEqual([r for r in rules(found) if r.startswith("잘 된 점")], [])

    def test_client_only_repo_gives_no_server_signal(self):
        found, _ = scan({"src/App.tsx": 'import { useEffect } from "react";\n'
                                        'const { data } = await supabase.auth.getUser();\n'
                                        'supabase.from("todos").select("*").eq("user_id", data.user.id);\n'})
        self.assertNotIn("잘 된 점: 서버에서 로그인을 확인해요", rules(found))
        self.assertNotIn("잘 된 점: 본인 데이터만 거르는 조건이 있어요", rules(found))

    def test_server_file_gives_server_signal(self):
        found, _ = scan({"app/api/todos/route.ts": SERVER_ROUTE})
        self.assertIn("잘 된 점: 서버에서 로그인을 확인해요", rules(found))
        self.assertIn("잘 된 점: 본인 데이터만 거르는 조건이 있어요", rules(found))

    def test_readme_sentence_is_not_rls_evidence(self):
        found, _ = scan({"README.md": "Remember to enable row level security and create policy for each table."})
        self.assertEqual([r for r in rules(found) if "RLS" in r or "정책" in r], [])


class CoverageTest(unittest.TestCase):
    """영역마다 본 것과 못 본 것."""

    def test_site_checks_only_secrets(self):
        _, cov = scan(SITE, kind="site")
        self.assertEqual(status(cov), {"secret": "ok", "env": "unknown", "rls": "unknown",
                                       "auth": "unknown", "owner": "unknown", "live": "unknown"})

    def test_site_secret_marks_issue(self):
        key = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
        _, cov = scan({"index.html": "<html></html>", "assets/app.js": f'var k = "{key}";'}, kind="site")
        self.assertEqual(status(cov)["secret"], "issue")

    def test_repo_with_migration_and_server_code(self):
        _, cov = scan({"supabase/migrations/1.sql": RLS_SQL,
                       "app/api/todos/route.ts": SERVER_ROUTE,
                       ".gitignore": ".env\n"})
        self.assertEqual(status(cov), {"secret": "ok", "env": "ok", "rls": "ok",
                                       "auth": "ok", "owner": "na", "live": "unknown"})

    def test_migration_without_rls_marks_issue(self):
        _, cov = scan({"supabase/migrations/1.sql": "create table todos (id int);"})
        self.assertEqual(status(cov)["rls"], "issue")

    def test_supabase_without_sql_is_unknown(self):
        _, cov = scan({"src/lib/sb.ts": 'import { createClient } from "@supabase/supabase-js";'})
        self.assertEqual(status(cov)["rls"], "unknown")

    def test_firebase_rules_are_unknown(self):
        _, cov = scan({"src/fb.ts": 'import { initializeApp } from "firebase/app";'})
        self.assertEqual(status(cov)["rls"], "unknown")

    def test_other_database_is_out_of_scope(self):
        _, cov = scan({"src/db.ts": 'import { PrismaClient } from "@prisma/client";'})
        self.assertEqual(status(cov)["rls"], "na")

    def test_committed_env_marks_issue(self):
        _, cov = scan({".env": "VITE_PUBLIC_NAME=demo\n"})
        self.assertEqual(status(cov)["env"], "issue")

    def test_live_is_ok_only_when_requests_were_sent(self):
        _, cov = scan({"src/a.ts": "export const a = 1;"})
        self.assertEqual(status(cov)["live"], "unknown")
        _, cov = scan({"src/a.ts": "export const a = 1;"}, live=True)
        self.assertEqual(status(cov)["live"], "ok")

    def test_no_facts_gives_empty_coverage(self):
        self.assertEqual(scanner.coverage([], {}), [])


class ReportTest(unittest.TestCase):
    """리포트가 못 본 영역을 초록으로 칠하지 않는다."""

    def card(self, page, label):
        m = re.search(r'<div class="num">(\d+)</div><div class="lab">' + re.escape(label) + "</div>", page)
        return int(m.group(1)) if m else None

    def test_unseen_areas_are_not_reported_as_fine(self):
        found, cov = scan(SITE, kind="site")
        page = report_html.build_html(found, "app", coverage=cov, kind="site")
        self.assertNotIn("급하게 고쳐야 할 문제는 없었어요", page)
        self.assertIn("5개 영역은 이번 점검으로 볼 수 없었어요", page)
        self.assertIn("GitHub 주소로 다시 점검하기", page)

    def test_notes_are_not_counted_as_good(self):
        found, cov = scan(SITE, kind="site")
        self.assertIn("Supabase publishable", rules(found))       # 공개 키 안내는 참고 항목
        page = report_html.build_html(found, "app", coverage=cov, kind="site")
        self.assertEqual(self.card(page, "잘 된 점"), 0)
        self.assertEqual(self.card(page, "확인 못 함"), 5)

    def test_markdown_report_has_coverage_table(self):
        found, cov = scan(SITE, kind="site")
        md = report.build_report(found, "app", coverage=cov, kind="site")
        self.assertIn("이번 점검이 본 것과 못 본 것", md)
        self.assertIn("❓ 확인 못 함", md)

    def test_report_without_coverage_still_builds(self):
        found, _ = scan(SITE, kind="site")
        page = report_html.build_html(found, "app")
        self.assertIn("app 점검 결과", page)
        self.assertIsNone(self.card(page, "확인 못 함"))

    def test_env_template_does_not_claim_file_contents(self):
        t = report._match_template({"severity": "CRITICAL", "rule": ".env not gitignored", "note": ""})
        self.assertNotIn("괜찮은 값만 들어있어", t["risk"])


class WorkerTest(unittest.TestCase):
    """웹 진단이 쓰는 scan_worker.py를 그대로 돌린다."""

    def test_site_scan_output(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src")
            for rel, text in SITE.items():
                write(src, rel, text)
            out = os.path.join(d, "result.json")
            subprocess.run([sys.executable, os.path.join(ROOT, "scan_worker.py"), src, out, "app.example", "site"],
                           check=True, cwd=d, capture_output=True)
            with open(out, encoding="utf-8") as fh:
                result = json.load(fh)
        self.assertEqual(result["kind"], "site")
        self.assertEqual(result["counts"]["GOOD"], 0)
        self.assertEqual(result["counts"]["UNKNOWN"], 5)
        self.assertEqual(len(result["coverage"]), 6)
        self.assertNotIn("라이브 점검 생략", result["html"])
        self.assertNotIn(d, result["html"])          # 서버 임시 폴더 경로가 리포트에 보이지 않는다


if __name__ == "__main__":
    unittest.main()
