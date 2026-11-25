#!/usr/bin/env python3
"""
report_html.py — vibescan findings를 '브라우저에서 바로 열리는 HTML 한 장'으로.
서버 불필요. 더블클릭하면 열리고, 카톡방에 파일로 공유 가능.
report.py의 템플릿(rule별 하드코딩)을 재사용. LLM 호출 없음.

리포트가 지키는 것: 문제를 못 찾은 것과 아예 보지 못한 것을 섞지 않는다.
  - '잘 된 점'에는 실제로 확인한 긍정 신호만 센다. 공개 키 안내 같은 참고 항목은 따로 둔다.
  - 점검 범위 표(coverage)를 주면 볼 수 없었던 영역을 회색으로 따로 적는다.
"""
import datetime, html
import report as R   # 기존 템플릿 재사용

# 피드백 설문 링크 — 구글폼 만들고 여기 붙여넣으면 리포트 하단에 버튼으로 나옴
SURVEY_URL = "https://forms.gle/gDRktdqPyNAh22877"


SEV_META = {
    "CRITICAL": {"ko": "지금 바로 고쳐야 해요", "band": "#B23A3A", "dot": "🔴", "bg": "#FBF1F0"},
    "WARN":     {"ko": "확인이 필요해요",       "band": "#C08A2D", "dot": "🟡", "bg": "#FBF6EC"},
    "INFO":     {"ko": "잘 되어 있어요",         "band": "#3E7C63", "dot": "🟢", "bg": "#EFF5F1"},
    "NOTE":     {"ko": "참고 (문제 아님)",       "band": "#8A96A3", "dot": "ℹ️", "bg": "#F2F4F6"},
}

# 점검 범위 표의 상태별 색. '확인 못 함'은 초록이 아닌 회색으로 둔다.
COV_STYLE = {
    "ok":      {"fg": "#2F6B53", "bg": "#EFF5F1"},
    "issue":   {"fg": "#8A5F12", "bg": "#FBF6EC"},
    "unknown": {"fg": "#44515E", "bg": "#E3E8ED"},
    "na":      {"fg": "#7A8691", "bg": "#F4F6F8"},
}

STYLE = """
  :root {
    --ink:#1C2530; --sub:#5A6673; --line:#E2E6EB; --paper:#F7F9FB; --card:#FFFFFF;
  }
  * { box-sizing:border-box; }
  body {
    margin:0; background:var(--paper); color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Apple SD Gothic Neo",
                "Malgun Gothic",sans-serif;
    line-height:1.65; font-size:16px;
  }
  .wrap { max-width:760px; margin:0 auto; padding:48px 20px 80px; }
  header .kicker { color:var(--sub); font-size:14px; margin:0 0 6px; }
  header h1 { font-size:30px; line-height:1.25; margin:0 0 8px; letter-spacing:-.01em; }
  header .when { color:var(--sub); font-size:14px; margin:0; }
  .reassure {
    margin:28px 0 8px; padding:16px 18px; background:#EEF3F8;
    border-radius:12px; color:#2C3A48; font-size:15px;
  }
  .summary { display:flex; gap:12px; margin:20px 0 8px; }
  .scard {
    flex:1; background:var(--bg); border:1px solid var(--line);
    border-top:3px solid var(--c); border-radius:12px; padding:18px 12px; text-align:center;
  }
  .scard .num { font-size:40px; font-weight:700; line-height:1; color:var(--c); }
  .scard .lab { font-size:13px; color:var(--sub); margin-top:8px; }
  section { margin-top:40px; }
  section h2 {
    font-size:19px; margin:0 0 4px; padding-bottom:10px;
    border-bottom:1px solid var(--line); display:flex; align-items:center; gap:8px;
  }
  section h2 .dot { font-size:15px; }
  section h2 .count {
    margin-left:auto; font-size:14px; color:var(--sub); font-weight:400;
  }
  .item {
    background:var(--card); border:1px solid var(--line); border-left:4px solid;
    border-radius:10px; padding:20px 22px; margin-top:16px;
  }
  .item h3 { font-size:17px; margin:0 0 10px; display:flex; align-items:baseline; gap:10px; }
  .item h3 .idx {
    flex:none; width:24px; height:24px; border-radius:50%; background:#EEF1F5;
    color:var(--sub); font-size:13px; font-weight:600; display:inline-flex;
    align-items:center; justify-content:center;
  }
  .item p { margin:0 0 12px; }
  .item .what { color:var(--ink); }
  .item .loc { margin:-4px 0 12px; }
  .item .loc code {
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px;
    background:#F0F2F5; padding:2px 7px; border-radius:5px; color:var(--sub);
    word-break:break-all;
  }
  .lbl {
    display:block; font-size:13px; font-weight:600; color:var(--sub); margin-bottom:6px;
  }
  .risk { margin:0 0 12px; }
  .risk p { margin:0; }
  .fix { margin-top:14px; }
  .promptwrap { position:relative; }
  .fix pre {
    background:#1C2530; color:#E8EDF2; padding:16px 18px; border-radius:10px;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13.5px;
    line-height:1.6; white-space:pre-wrap; word-break:break-word; margin:0;
  }
  .fix button {
    position:absolute; top:10px; right:10px; background:#33414F; color:#fff;
    border:0; border-radius:7px; padding:6px 12px; font-size:12.5px; cursor:pointer;
  }
  .fix button:hover { background:#44566A; }
  .fix button.done { background:#3E7C63; }
  .covcard {
    background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:4px 20px; margin-top:16px;
  }
  .covrow { display:flex; gap:12px; padding:14px 0; border-bottom:1px solid var(--line); }
  .covrow:last-child { border-bottom:0; }
  .covrow .ic { flex:none; font-size:16px; line-height:1.6; }
  .covhead { display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
  .covhead b { font-size:15.5px; }
  .pill { font-size:12.5px; font-weight:600; padding:2px 9px; border-radius:999px; white-space:nowrap; }
  .covbody p { margin:4px 0 0; font-size:14.5px; color:var(--sub); }
  .steps {
    background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:18px 22px; margin-top:16px;
  }
  .steps h3 { font-size:16px; margin:0 0 10px; }
  .steps ol { margin:0; padding-left:20px; }
  .steps li { margin-bottom:12px; }
  .steps li:last-child { margin-bottom:0; }
  .steps li p { margin:2px 0 0; font-size:14.5px; color:var(--sub); }
  .steps .fix { margin-top:10px; }
  .steps a.human { color:#1F5F5B; font-weight:600; }
  footer {
    margin-top:48px; padding-top:20px; border-top:1px solid var(--line);
    color:var(--sub); font-size:13px;
  }
  @media (max-width:520px) {
    .summary { flex-wrap:wrap; }
    .scard { flex:1 1 40%; }
    header h1 { font-size:24px; }
  }
"""

SCRIPT = """
function cp(i){
  const el=document.getElementById('p'+i);
  navigator.clipboard.writeText(el.innerText).then(()=>{
    const b=el.parentElement.querySelector('button');
    b.textContent='복사됨'; b.classList.add('done');
    setTimeout(()=>{b.textContent='복사'; b.classList.remove('done');},1500);
  });
}
"""


def _esc(s):
    return html.escape(str(s or ""))


def build_html(findings, target_name="내 앱", coverage=None, kind="repo"):
    """coverage: scanner.coverage()의 결과. 주면 '본 것과 못 본 것' 표와 '확인 못 함' 카드가 들어간다.
    kind: "site"면 GitHub 주소로 다시 점검하라는 안내가 추가된다."""
    return _build_html_inner(findings, target_name, coverage, kind).replace("__SURVEY_URL__", SURVEY_URL)


def _build_html_inner(findings, target_name="내 앱", coverage=None, kind="repo"):
    now = datetime.datetime.now().strftime("%Y년 %m월 %d일 %H:%M")
    crit = [f for f in findings if f["severity"] == "CRITICAL"]
    warn = [f for f in findings if f["severity"] == "WARN"]
    info = [f for f in findings if f["severity"] == "INFO"]
    good = [f for f in info if R.info_kind(f) == "good"]
    notes = [f for f in info if R.info_kind(f) == "note"]
    cov = R.cov_counts(coverage)

    # 항목 카드 HTML. group은 SEV_META의 키(잘 된 점은 INFO, 참고는 NOTE)
    def item_block(f, idx, group):
        t = R._match_template(f)
        meta = SEV_META[group]
        loc = f.get("file", "")
        if loc and f.get("line"):
            loc = f"{loc}:{f['line']}"
        parts = [f'<article class="item" style="border-left-color:{meta["band"]}">']
        parts.append(f'<h3><span class="idx">{idx}</span>{_esc(t["title"])}</h3>')
        if t.get("what"):
            parts.append(f'<p class="what">{_esc(t["what"])}</p>')
        if loc:
            parts.append(f'<p class="loc"><code>{_esc(loc)}</code></p>')
        if group in ("CRITICAL", "WARN") and t.get("risk"):
            parts.append(f'<div class="risk"><span class="lbl">왜 위험한가요</span><p>{_esc(t["risk"])}</p></div>')
        if t.get("fix"):
            parts.append('<div class="fix"><span class="lbl">고치는 법 — 아래를 복사해 Cursor/Lovable에 붙여넣으세요</span>')
            parts.append(f'<div class="promptwrap"><pre id="p{idx}">{_esc(t["fix"])}</pre>'
                         f'<button onclick="cp({idx})">복사</button></div></div>')
        parts.append('</article>')
        return "\n".join(parts)

    counter = [0]

    def findings_section(group, items):
        if not items:
            return ""
        meta = SEV_META[group]
        blocks = []
        for f in items:
            counter[0] += 1
            blocks.append(item_block(f, counter[0], group))
        return (f'<section class="sev-{group.lower()}">'
                f'<h2><span class="dot">{meta["dot"]}</span>{meta["ko"]} '
                f'<span class="count">{len(items)}</span></h2>'
                + "\n".join(blocks) + '</section>')

    # 점검 범위: 본 것과 못 본 것
    def coverage_section():
        if not coverage:
            return ""
        rows = []
        for r in coverage:
            icon, label = R.COV_META[r["status"]]
            st = COV_STYLE[r["status"]]
            rows.append(
                f'<div class="covrow"><span class="ic">{icon}</span><div class="covbody">'
                f'<div class="covhead"><b>{_esc(r["label"])}</b>'
                f'<span class="pill" style="color:{st["fg"]};background:{st["bg"]}">{label}</span></div>'
                f'<p>{_esc(r["detail"])}</p></div></div>')
        steps = ""
        if cov["unknown"]:
            lis = []
            for key, title, body in R.next_steps(kind):
                extra = ""
                if key == "ai":
                    extra = (f'<div class="fix"><div class="promptwrap"><pre id="p900">{_esc(R.SELF_CHECK_PROMPT)}</pre>'
                             f'<button onclick="cp(900)">복사</button></div></div>')
                elif key == "human" and R.HUMAN_CHECK_URL:
                    extra = (f'<p><a class="human" href="{R.HUMAN_CHECK_URL}" target="_blank" rel="noopener">'
                             f'사람 점검 안내 보기 →</a></p>')
                lis.append(f'<li><b>{_esc(title)}</b><p>{_esc(body)}</p>{extra}</li>')
            steps = ('<div class="steps"><h3>볼 수 없었던 영역은 이렇게 확인할 수 있어요</h3><ol>'
                     + "".join(lis) + '</ol></div>')
        return ('<section class="cov"><h2><span class="dot">🔎</span>이번 점검이 본 것과 못 본 것 '
                f'<span class="count">{len(coverage)}개 영역 중 {cov["ok"] + cov["issue"]}개 확인</span></h2>'
                '<div class="covcard">' + "".join(rows) + '</div>' + steps + '</section>')

    # 급한 것 → 점검 범위 → 잘 된 점 → 참고 순서
    sections = [
        findings_section("CRITICAL", crit),
        findings_section("WARN", warn),
        coverage_section(),
        findings_section("INFO", good),
        findings_section("NOTE", notes),
    ]

    # 요약 숫자. '잘 된 점'은 확인한 긍정 신호만 센다.
    cards = [("CRITICAL", len(crit), "지금 고쳐야 함"),
             ("WARN", len(warn), "확인 필요"),
             ("INFO", len(good), "잘 된 점")]
    if coverage:
        cards.append(("NOTE", cov["unknown"], "확인 못 함"))
    summary_cards = []
    for group, num, label in cards:
        meta = SEV_META[group]
        summary_cards.append(
            f'<div class="scard" style="--c:{meta["band"]};--bg:{meta["bg"]}">'
            f'<div class="num">{num}</div><div class="lab">{label}</div></div>'
        )

    reassure = R.headline(crit, warn, coverage)

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(target_name)} 보안 점검 결과</title>
<style>{STYLE}</style>
</head>
<body>
<div class="wrap">
  <header>
    <p class="kicker">AI로 만든 앱 보안 점검</p>
    <h1>{_esc(target_name)} 점검 결과</h1>
    <p class="when">{now}</p>
  </header>

  <div class="reassure">{_esc(reassure)}</div>
  <div class="summary">{''.join(summary_cards)}</div>

  {''.join(sections)}

  <footer>
    이 결과는 자동 점검이에요. '확인이 필요해요' 항목은 실제 문제가 아닐 수도 있어요.
    문제를 찾지 못했다는 것이 안전하다는 뜻은 아니에요.
    고친 뒤 다시 점검하면 해결됐는지 볼 수 있어요.
    <div style="margin-top:20px;padding:18px;background:#EEF3F8;border-radius:12px;text-align:center">
      <div style="color:#2C3A48;font-size:14px;margin-bottom:10px">이 리포트, 이해가 잘 되셨나요? 2분이면 돼요 🙏</div>
      <a href="__SURVEY_URL__" target="_blank"
         style="display:inline-block;background:#1F5F5B;color:#fff;text-decoration:none;
                padding:11px 22px;border-radius:9px;font-size:14px;font-weight:600">
        피드백 남기기
      </a>
    </div>
  </footer>
</div>
<script>{SCRIPT}</script>
</body>
</html>"""


if __name__ == "__main__":
    # 앱 주소만 넣었을 때의 전형적인 결과를 모사한 샘플
    sample = [
        {"severity": "INFO", "rule": "Supabase publishable",
         "file": "assets/index-abc.js", "line": 1, "match": "sb_pub********83zD", "note": ""},
    ]
    cov = [
        {"key": "secret", "label": "비밀 키 노출", "status": "ok",
         "detail": "브라우저가 내려받는 화면 코드 4개 파일에서 비밀 키 모양을 찾아봤어요."},
        {"key": "env", "label": "비밀 설정 파일(.env) 관리", "status": "unknown",
         "detail": "앱 주소만으로는 저장소 설정을 볼 수 없어요. GitHub 주소로 점검하면 확인돼요."},
        {"key": "rls", "label": "데이터 잠금(RLS) 설정", "status": "unknown",
         "detail": "잠금 설정은 데이터베이스 안에 있어서 화면 코드에는 보이지 않아요."},
    ]
    out = build_html(sample, "내앱.lovable.app", coverage=cov, kind="site")
    open("report_sample.html", "w", encoding="utf-8").write(out)
    print("report_sample.html 생성됨")
