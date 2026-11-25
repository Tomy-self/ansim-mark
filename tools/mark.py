#!/usr/bin/env python3
"""
tools/mark.py — 안심마크 2단계(사람 확인)의 공개 확인서와 견본 리포트를 만든다.

  python tools/mark.py sample            # docs/sample-report.html, docs/sample-cert.html 다시 만들기
  python tools/mark.py cert 기록.json     # 확인서 발급 → docs/v/<확인 번호>.html

점검 확인서가 말하는 것은 "그 날짜에, 그 범위를, 이렇게 확인했다"까지다.
앱 전체가 괜찮다는 뜻으로 읽히는 말(안전, 인증, 공인)은 쓰지 않는다.
  배경: 스캔 통과 표시를 단 사이트에서 문제가 나온 사례(Hacker Safe, 2008),
        재점검 없이 표시를 유지해 제재받은 사례(TRUSTe, 2014)

기록 파일(JSON) 예시는 SAMPLE_CERT 참고. 고객 앱 이름이 들어가므로 기록 파일은 git에 올리지 않는
reports/ 아래에 둔다. 만들어진 docs/v/<번호>.html은 고객이 공개에 동의한 경우에만 배포한다.
"""
import datetime, html, json, os, secrets, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import report
import report_html
import scanner

WEB = os.path.join(ROOT, "docs")
SITE = os.environ.get("MARK_SITE", "https://example.com")   # 확인서를 공개할 주소
VALID_DAYS = 90
STATUSES = ("ok", "issue", "unknown", "na")
RISKY_WORDS = ("안전합니다", "안전해요", "인증", "공인", "보증합니다", "보증해요")


def esc(s):
    return html.escape(str(s or ""))


# ---------------------------------------------------------------
# 리포트 견본: 가상의 저장소를 실제 스캐너로 점검한 결과 (손으로 꾸민 화면이 아님)
# ---------------------------------------------------------------
SAMPLE_REPO = {
    ".env": ("VITE_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\n"
             "VITE_SUPABASE_PUBLISHABLE_KEY=sb_publishable_AbCdEfGhIjKlMnOpQrStUv12\n"),
    "supabase/migrations/001_init.sql": (
        "create table todos (id uuid primary key, user_id uuid, title text);\n"
        "alter table todos enable row level security;\n"
        'create policy "own todos" on todos for all using (auth.uid() = user_id) with check (auth.uid() = user_id);\n'
        "\n"
        "create table notes (id uuid primary key, user_id uuid, body text);\n"
        "alter table notes enable row level security;\n"
        'create policy "anyone can read" on notes for select using (true);\n'),
    "app/api/todos/route.ts": (
        "export async function POST(req) {\n"
        "  const { data: { user } } = await supabase.auth.getUser();\n"
        '  if (!user) return new Response("로그인이 필요해요", { status: 401 });\n'
        '  await supabase.from("todos").insert({ title: "할 일", user_id: user.id });\n'
        '  return supabase.from("todos").select("*").eq("user_id", user.id);\n'
        "}\n"),
    "src/App.tsx": ('import { useEffect, useState } from "react";\n'
                    "export default function App() { return null; }\n"),
}

SAMPLE_BANNER = ('<div style="margin:0 0 24px;padding:12px 16px;background:#E3E8ED;border-radius:10px;'
                 'color:#44515E;font-size:14px">견본이에요. 가상의 앱을 실제 점검기로 돌린 결과를 보여 드려요.</div>')


def build_sample_report():
    with tempfile.TemporaryDirectory() as d:
        for rel, text in SAMPLE_REPO.items():
            path = os.path.join(d, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        found = scanner.run(d, kind="repo")
        cov = scanner.coverage(found, scanner.FACTS, live=False)
        prefix = os.path.realpath(d).rstrip("/") + "/"
        for f in found:                       # 임시 폴더 경로가 화면에 보이지 않게
            if isinstance(f.get("file"), str):
                f["file"] = f["file"].replace(prefix, "").replace(d.rstrip("/") + "/", "")
    page = report_html.build_html(found, "예시 앱", coverage=cov, kind="repo")
    page = page.replace('<meta charset="utf-8">', '<meta charset="utf-8">\n<meta name="robots" content="noindex">', 1)
    return page.replace('<div class="wrap">', '<div class="wrap">\n  ' + SAMPLE_BANNER, 1)


# ---------------------------------------------------------------
# 점검 확인서
# ---------------------------------------------------------------
SAMPLE_CERT = {
    "id": "sample",
    "sample": True,
    "app_name": "예시 가계부 앱",
    "app_url": "",
    "checked_on": "2026-11-20",
    "version": "2026-11-19에 배포된 판",
    "method": [
        "앱 주인의 서면 동의를 받은 뒤, 로그인하지 않은 상태로 테이블마다 읽기 요청을 1건씩 보냈어요.",
        "저장소의 코드와 데이터 잠금 설정(SQL)을 읽었어요.",
        "쓰기, 수정, 삭제 요청은 보내지 않았어요.",
    ],
    "rows": [
        {"label": "로그인 없이 회원 데이터가 읽히는지", "status": "ok",
         "detail": "테이블 4개에 읽기 요청을 1건씩 보냈고, 모두 막혀 있었어요."},
        {"label": "비밀 키 노출", "status": "ok",
         "detail": "화면 코드와 저장소에서 비밀 키를 찾지 못했어요."},
        {"label": "서버 기능의 로그인 확인", "status": "ok",
         "detail": "데이터를 바꾸는 서버 기능 3개에 로그인 확인이 있었어요."},
        {"label": "남의 데이터 접근 차단(본인 것만)", "status": "ok",
         "detail": "빠진 곳 1건을 찾아 고쳤고, 고친 뒤 다시 확인했어요."},
        {"label": "쓰기 정책(추가·수정·삭제)", "status": "unknown",
         "detail": "쓰기 요청은 보내지 않아요. 코드에 적힌 정책은 읽었지만 실제로 막히는지는 확인하지 못했어요."},
        {"label": "파일 저장소와 rpc 함수", "status": "unknown",
         "detail": "이번 점검 범위에 넣지 않았어요."},
    ],
    "fixed": ["주문 상세를 여는 서버 기능에 '본인 것만' 확인을 추가했어요."],
}

CERT_STYLE = """
  :root{--paper:#EEF1F4;--card:#FBFCFD;--ink:#1A2733;--sub:#5B6875;--line:#DDE3E9;--teal:#1F5F5B}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--paper);color:var(--ink);line-height:1.65;-webkit-font-smoothing:antialiased;
       font-family:"Pretendard","Pretendard Variable",-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic",sans-serif}
  .wrap{max-width:720px;margin:0 auto;padding:48px 22px 60px}
  a{color:var(--teal)}
  .banner{padding:12px 16px;border-radius:10px;font-size:14px;margin-bottom:20px}
  .banner.sample{background:#E3E8ED;color:#44515E}
  .banner.bad{background:#F7ECEB;color:#B23A3A;font-weight:600}
  .kicker{color:var(--teal);font-weight:600;font-size:15px;margin-bottom:10px}
  h1{font-size:30px;line-height:1.3;letter-spacing:-.02em;margin-bottom:12px}
  .lead{font-size:16.5px;margin-bottom:22px}
  .meta{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:6px 22px;margin-bottom:8px}
  .meta div{display:flex;gap:16px;padding:11px 0;border-bottom:1px solid var(--line);font-size:15px}
  .meta div:last-child{border-bottom:0}
  .meta dt{flex:none;width:92px;color:var(--sub)}
  .meta dd{word-break:break-all}
  h2{font-size:19px;margin:34px 0 12px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:4px 22px}
  .row{display:flex;gap:12px;padding:14px 0;border-bottom:1px solid var(--line)}
  .row:last-child{border-bottom:0}
  .row .ic{flex:none;font-size:16px;line-height:1.6}
  .head{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
  .head b{font-size:15.5px}
  .pill{font-size:12.5px;font-weight:600;padding:2px 9px;border-radius:999px;white-space:nowrap}
  .row p{margin-top:4px;font-size:14.5px;color:var(--sub)}
  ul.plain{padding-left:20px}
  ul.plain li{font-size:15px;color:#33414E;margin-bottom:5px}
  .small{font-size:13.5px;color:var(--sub);margin-top:14px}
  .use{background:var(--card);border:1px dashed var(--line);border-radius:14px;padding:18px 22px;margin-top:34px;font-size:14.5px;color:#33414E}
  footer{color:var(--sub);font-size:13px;margin-top:40px;padding-top:20px;border-top:1px solid var(--line)}
  @media (max-width:520px){ h1{font-size:25px} .meta dt{width:76px} }
"""


def kdate(d):
    return f"{d.year}년 {d.month}월 {d.day}일"


def check_record(rec):
    """기록 파일에 빠진 것이 없는지 확인. 문제를 문장 목록으로 돌려준다."""
    problems = []
    for key in ("app_name", "checked_on", "rows"):
        if not rec.get(key):
            problems.append(f"'{key}' 값이 없어요.")
    try:
        datetime.date.fromisoformat(rec.get("checked_on", ""))
    except ValueError:
        problems.append("'checked_on'은 2026-11-20 같은 날짜 형식이어야 해요.")
    for i, row in enumerate(rec.get("rows") or [], 1):
        if not row.get("label") or not row.get("detail"):
            problems.append(f"rows {i}번에 label 또는 detail이 없어요.")
        if row.get("status") not in STATUSES:
            problems.append(f"rows {i}번의 status는 {', '.join(STATUSES)} 중 하나여야 해요.")
    return problems


def risky_words(rec):
    """앱 전체가 괜찮다는 뜻으로 읽힐 수 있는 말이 들어갔는지."""
    text = json.dumps(rec, ensure_ascii=False)
    return [w for w in RISKY_WORDS if w in text]


def build_cert(rec):
    checked = datetime.date.fromisoformat(rec["checked_on"])
    until = checked + datetime.timedelta(days=int(rec.get("valid_days", VALID_DAYS)))
    cid = rec["id"]

    banners = ""
    if rec.get("sample"):
        banners += '<div class="banner sample">견본이에요. 실제 앱의 점검 결과가 아니에요.</div>'
    if rec.get("revoked"):
        note = esc(rec.get("revoked_note") or "중대한 문제가 확인되어 이 확인서를 거둬들였어요.")
        banners += f'<div class="banner bad">거둬들임: {note}</div>'
    banners += ('<div class="banner bad" id="expired" style="display:none">'
                '유효 기간이 지났어요. 점검일 뒤의 상태는 이 문서로 알 수 없어요.</div>')

    meta = [("점검일", kdate(checked)),
            ("유효 기간", f"{kdate(until)}까지")]
    if rec.get("version"):
        meta.append(("점검한 판", rec["version"]))
    if rec.get("app_url"):
        meta.append(("앱 주소", rec["app_url"]))
    meta += [("검수자", rec.get("inspector") or "안심마크 검증관"), ("확인 번호", cid)]
    meta_html = "".join(f"<div><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>" for k, v in meta)

    rows = []
    for row in rec["rows"]:
        icon, label = report.COV_META[row["status"]]
        st = report_html.COV_STYLE[row["status"]]
        rows.append(f'<div class="row"><span class="ic">{icon}</span><div>'
                    f'<div class="head"><b>{esc(row["label"])}</b>'
                    f'<span class="pill" style="color:{st["fg"]};background:{st["bg"]}">{label}</span></div>'
                    f'<p>{esc(row["detail"])}</p></div></div>')

    method = ""
    if rec.get("method"):
        method = ('<h2>이렇게 확인했어요</h2><ul class="plain">'
                  + "".join(f"<li>{esc(m)}</li>" for m in rec["method"]) + "</ul>")
    fixed = ""
    if rec.get("fixed"):
        fixed = ('<h2>점검하면서 고친 것</h2><ul class="plain">'
                 + "".join(f"<li>{esc(m)}</li>" for m in rec["fixed"]) + "</ul>")
    use = ""
    if rec.get("sample"):
        use = ('<div class="use"><b>받으면 이렇게 쓸 수 있어요.</b> 내 사이트 아래쪽에 이 페이지로 오는 링크를 달아 두면, '
               '방문한 사람이 언제 무엇을 점검받았는지 직접 볼 수 있어요. 링크 문구 예: 점검 확인서 보기 (2026-11-20)</div>')

    robots = "" if rec.get("index") else '<meta name="robots" content="noindex">\n'
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{robots}<title>{esc(rec["app_name"])} 점검 확인서</title>
<style>{CERT_STYLE}</style>
</head>
<body>
<div class="wrap">
  {banners}
  <p class="kicker">점검 확인서</p>
  <h1>{esc(rec["app_name"])}</h1>
  <p class="lead"><b>{kdate(checked)}</b>에 아래 범위를 점검했어요. 그날의 상태를 적은 문서예요.</p>
  <dl class="meta">{meta_html}</dl>

  <h2>확인한 범위와 결과</h2>
  <div class="card">{''.join(rows)}</div>

  {method}
  {fixed}

  <h2>이 확인서가 말하지 않는 것</h2>
  <ul class="plain">
    <li>앱 전체가 안전하다는 뜻은 아니에요. 위에 적은 범위만 확인했어요.</li>
    <li>점검일 뒤에 바뀐 코드와 설정은 반영되지 않아요.</li>
    <li>"확인 못 함"으로 적힌 영역은 점검하지 못한 영역이에요.</li>
  </ul>
  <p class="small">중대한 문제가 확인되면 이 페이지에 "거둬들임"으로 표시해요. 유효 기간이 지나면 다시 점검해야 해요.</p>
  {use}
  <footer>AI 앱 안심마크 2단계(사람 확인) 확인서예요. 확인 번호로 원본을 대조할 수 있어요.</footer>
</div>
<script>
  if (new Date() > new Date("{until.isoformat()}T23:59:59+09:00")) document.getElementById('expired').style.display = 'block';
</script>
</body>
</html>"""


def write(rel, text):
    path = os.path.join(WEB, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def main(argv):
    if len(argv) >= 1 and argv[0] == "sample":
        print("만든 파일:", write("sample-report.html", build_sample_report()))
        print("만든 파일:", write("sample-cert.html", build_cert(dict(SAMPLE_CERT))))
        return 0

    if len(argv) >= 2 and argv[0] == "cert":
        with open(argv[1], encoding="utf-8") as fh:
            rec = json.load(fh)
        problems = check_record(rec)
        if problems:
            print("기록 파일을 고쳐 주세요:")
            for p in problems:
                print("  -", p)
            return 1
        if not rec.get("id"):
            rec["id"] = secrets.token_hex(4)      # 추측하기 어려운 확인 번호
        for w in risky_words(rec):
            print(f"주의: '{w}'라는 말이 들어 있어요. 앱 전체가 괜찮다는 뜻으로 읽힐 수 있으니 범위와 날짜로 바꿔 쓰세요.")
        path = write(os.path.join("v", rec["id"] + ".html"), build_cert(rec))
        url = f"{SITE}/v/{rec['id']}"
        label = f"점검 확인서 보기 ({rec['checked_on']})"
        print("점검 확인서를 만들었어요:", path)
        print("공개 주소(배포한 뒤):", url)
        print("\n고객 사이트에 달 링크:")
        print(f'  <a href="{url}" target="_blank" rel="noopener">{label}</a>')
        print("\n고객이 AI 도구에 붙여 넣을 문장:")
        print(f'  사이트 맨 아래에 "{label}"라는 링크를 추가해 줘. 주소는 {url} 이고 새 탭으로 열리게 해 줘.')
        print("\n배포 전에 확인: 고객이 이 페이지의 공개에 동의했는지.")
        return 0

    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
