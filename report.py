#!/usr/bin/env python3
"""
report.py — vibescan findings를 비개발자용 마크다운 리포트로 변환.
LLM 호출 없음. 전부 rule 기반 하드코딩 템플릿 (결정론적).

사용:
  from report import build_report
  md = build_report(findings, target_name)
"""
import datetime
import os

# ---------------------------------------------------------------
# rule 매칭 → 비개발자용 템플릿
#   각 템플릿: title / what(확인된 사실) / risk(실제 위험) / fix(붙여넣을 프롬프트)
#   {var} 자리는 finding에서 채움
# ---------------------------------------------------------------
SEV_KO = {
    "CRITICAL": ("🔴", "지금 바로 고쳐야 해요"),
    "WARN":     ("🟡", "확인이 필요해요"),
    "INFO":     ("🟢", "참고하세요 (문제 아님)"),
}

# 점검 범위 표의 상태 표기 (scanner.coverage()의 status)
COV_META = {
    "ok":      ("✅", "확인함 · 문제 못 찾음"),
    "issue":   ("⚠️", "확인함 · 살펴볼 것 있음"),
    "unknown": ("❓", "확인 못 함"),
    "na":      ("➖", "해당 없음"),
}

# 사람이 직접 봐 주는 점검 안내 위치
HUMAN_CHECK_URL = os.environ.get("HUMAN_CHECK_URL", "")   # 2단계(사람 확인) 신청 안내 주소. 비어 있으면 링크를 넣지 않는다

# 못 본 영역을 스스로 확인할 때 AI 코딩 도구에 붙여 넣는 문장
SELF_CHECK_PROMPT = ("이 프로젝트의 Supabase 설정과 마이그레이션 파일을 보고, RLS가 꺼진 테이블과 "
                     "누구에게나 열린 정책을 목록으로 보여 줘. 고치기 전에 테이블마다 누가 읽고 써야 하는지 "
                     "나에게 먼저 물어봐.")


def info_kind(f):
    """INFO 항목을 '잘 된 점'(good)과 '참고'(note)로 나눈다.
    공개 키 안내나 점검의 한계 같은 참고 항목을 잘 된 점으로 세지 않기 위해."""
    return "good" if f.get("rule", "").startswith("잘 된 점") else "note"


def cov_counts(coverage):
    c = {"ok": 0, "issue": 0, "unknown": 0, "na": 0}
    for r in coverage or []:
        c[r["status"]] = c.get(r["status"], 0) + 1
    return c


def headline(crit, warn, coverage):
    """리포트 첫 문장. 볼 수 없었던 영역이 있으면 '문제없음'으로 읽히게 쓰지 않는다."""
    c = cov_counts(coverage)
    unknown = c["unknown"]
    if crit:
        s = "빨간 항목부터 고치면 됩니다. 하나씩 따라 하면 돼요."
    elif warn:
        s = "당장 위험한 건 없어요. 확인이 필요한 항목만 하나씩 살펴보세요."
    elif not coverage:
        return "급하게 고쳐야 할 문제는 발견되지 않았어요."
    elif unknown:
        return (f"확인할 수 있었던 {c['ok'] + c['issue']}개 영역에서는 문제를 찾지 못했어요. "
                f"{unknown}개 영역은 이번 점검으로 볼 수 없었어요. 그 영역은 아직 모르는 상태예요.")
    else:
        return "확인한 영역에서는 급하게 고칠 문제를 찾지 못했어요."
    if unknown:
        s += f" 이번 점검으로 볼 수 없었던 영역 {unknown}개도 아래에 적어 뒀어요."
    return s


def next_steps(kind="repo"):
    """볼 수 없었던 영역을 확인하는 방법. 스스로 할 수 있는 것부터, 사람 점검은 마지막에."""
    steps = [
        ("ai", "AI 도구에게 물어보기",
         "아래 문장을 Cursor나 Lovable에 붙여 넣으면 잠금이 꺼진 테이블을 목록으로 보여 줘요."),
        ("advisor", "Supabase 대시보드에서 직접 보기",
         "Supabase를 쓴다면 대시보드에서 Advisors → Security Advisor를 열어 보세요. "
         "빨간 경고가 있으면 그것부터 고치면 돼요. 무료이고 5분이면 돼요."),
    ]
    if kind == "site":
        steps.append(("repo", "GitHub 주소로 다시 점검하기",
                      "저장소가 공개돼 있다면 GitHub 주소를 넣어 보세요. "
                      ".env 관리, 데이터 잠금 SQL, 서버 코드까지 살펴봐요."))
    steps.append(("human", "사람에게 맡기기",
                  "직접 보기 어렵다면 사람이 확인해 드려요. 서면 동의를 받은 뒤 읽기 요청만 보내서 "
                  "실제로 막히는지 확인해요."))
    return steps


def _match_template(f):
    rule = f.get("rule", "")
    note = f.get("note", "")

    # --- 시크릿 / .env ---
    if ".env not gitignored" in rule or ".env" in rule and "gitignore" in note:
        return {
            "title": "비밀 설정 파일(.env)이 깃허브에 올라갈 수 있어요",
            "what": "`.env` 파일이 `.gitignore` 목록에 없습니다. 이 상태로 깃허브에 올리면 파일 안의 내용이 그대로 공개됩니다.",
            "risk": "파일 안에 공개돼도 되는 값만 있다면 지금 당장 피해는 없어요. 하지만 결제 키나 관리자 비밀번호가 들어 있거나 나중에 추가하면, 그대로 인터넷에 공개됩니다. 남이 그 키로 요금을 쓰거나 데이터를 훔칠 수 있어요.",
            "fix": "`.gitignore` 파일 맨 아래에 `.env` 를 추가해줘. 그리고 이미 깃에 올라간 `.env` 가 있다면 깃 기록에서도 지우는 방법을 알려줘.",
        }
    if "service_role" in rule or "시크릿 키" in rule:
        return {
            "title": "마스터 열쇠(service_role/secret 키)가 코드에 있어요",
            "what": "데이터베이스를 통째로 열 수 있는 '마스터 키'가 앱 코드 안에서 발견됐습니다.",
            "risk": "이 키는 모든 보안 잠금을 무시합니다. 코드에 있으면 누구나 이 키로 당신의 데이터 전체를 읽고, 고치고, 지울 수 있어요. 가장 위험한 종류의 노출입니다.",
            "fix": "코드에서 secret(service_role) 키를 전부 찾아서 제거하고, 서버 환경변수로만 쓰도록 바꿔줘. 그리고 이미 노출된 이 키는 Supabase 대시보드에서 새 키로 교체(rotate)하는 방법을 알려줘.",
        }

    # --- 라이브: 읽기 뚫림 ---
    if "테이블 읽기" in rule and ("RLS 없음" in note or "데이터를 읽음" in note):
        leaked = ""
        if "유출 컬럼" in note:
            leaked = note.split("유출 컬럼:")[-1].strip()
        return {
            "title": "로그인 안 한 사람도 데이터를 볼 수 있어요",
            "what": f"로그인 없이 보낸 요청에 데이터베이스가 실제 내용을 그대로 돌려줬습니다." + (f" (보인 항목: {leaked})" if leaked else ""),
            "risk": "누구든 당신의 앱 주소만 알면, 회원가입도 로그인도 없이 저장된 데이터를 통째로 열어볼 수 있다는 뜻입니다. 개인정보가 들어있다면 유출 사고입니다.",
            "fix": "Supabase에서 이 테이블에 RLS(행 수준 보안)를 켜고, 로그인한 본인만 자기 데이터를 볼 수 있게 정책을 만들어줘. 비개발자도 따라 할 수 있게 SQL을 그대로 알려줘.",
        }

    # --- 라이브: 읽기 모호 (빈 배열) ---
    if "테이블 읽기" in rule and "빈 배열" in note:
        return {
            "title": "밖에서는 잠겼는지 판단할 수 없어요",
            "what": "로그인 없이 요청했더니 '빈 결과'가 돌아왔습니다. 보안 잠금(RLS)이 작동해서일 수도 있지만, 원래 데이터가 없어서 비어 보이는 것일 수도 있어요. 밖에서는 둘을 구분할 수 없어서 '안전'이라고 말하지 않을게요.",
            "risk": "지금 당장의 위험은 낮아요. 하지만 데이터가 실제로 있는데도 안 보이는 건지, 아니면 그냥 테이블이 빈 건지는 앱 안에서만 확인할 수 있어요.",
            "fix": "이 테이블에 RLS가 켜져 있고, 로그인한 사용자가 자기 데이터만 볼 수 있는 정책이 제대로 걸려 있는지 확인해줘. 켜져 있지 않다면 켜는 SQL을 알려줘.",
        }

    # --- 라이브: 쓰기 권한 ---
    if "쓰기 권한" in rule:
        return {
            "title": "낯선 사람이 데이터를 넣거나 지울 수 있을지도 몰라요",
            "what": "로그인 없이도 이 테이블에 '쓰기'(추가·수정·삭제) 권한이 열려 있습니다. 실제로 막혀 있는지는 밖에서 확인할 수 없어요 (안전을 위해 실제로 써보지는 않았습니다).",
            "risk": "만약 쓰기 잠금(정책)이 없다면, 아무나 당신의 앱에 가짜 데이터를 넣거나 남의 데이터를 지울 수 있습니다. 읽기만 막고 쓰기를 깜빡하는 건 아주 흔한 실수예요.",
            "fix": "이 테이블에 로그인한 본인만 자기 데이터를 추가/수정/삭제할 수 있도록 INSERT·UPDATE·DELETE 정책이 걸려 있는지 확인해줘. 없으면 만들어주는 SQL을 알려줘.",
        }

    # --- 서버 함수 인증 누락 ---
    if "서버 함수 인증" in rule:
        return {
            "title": "앱의 '뒷문'이 잠기지 않았어요",
            "what": "화면(앞문)은 로그인으로 막혀 있지만, 데이터를 실제로 처리하는 서버 기능(뒷문)에는 로그인 확인이 없습니다.",
            "risk": "화면을 우회해서 뒷문으로 직접 요청을 보내면, 로그인 안 한 사람도 이 기능을 쓸 수 있어요. 화면만 막는 건 '문에 커튼만 친 것'과 같습니다.",
            "fix": "이 서버 함수에 로그인 확인(인증 미들웨어)을 추가해서, 로그인한 사용자만 실행할 수 있게 해줘.",
        }

    # --- IDOR ---
    if "IDOR" in rule or "소유권" in rule:
        return {
            "title": "남의 데이터에도 손댈 수 있을지 몰라요",
            "what": "데이터를 가져오거나 바꾸는 코드에서, '이게 내 데이터가 맞는지' 확인하는 조건이 안 보입니다.",
            "risk": "확인이 없으면, 주소의 번호(id)만 바꿔서 남의 데이터를 열어보거나 고칠 수 있어요. 예를 들어 내 주문 대신 남의 주문을 보게 되는 식입니다.",
            "fix": "이 쿼리에 '로그인한 본인 것만' 걸러내는 조건(user_id = 현재 사용자)이 들어가 있는지 확인하고, 없으면 추가해줘.",
        }

    # --- 마이그레이션 정적 판정 ---
    if "RLS 꺼진 테이블" in rule:
        return {
            "title": "보안 잠금(RLS)을 켜는 코드가 안 보여요",
            "what": f"데이터베이스 테이블을 만드는 코드는 있는데, 그 테이블에 보안 잠금(RLS)을 켜는 줄이 없습니다. ({f.get('match','')})",
            "risk": "대시보드에서 따로 켰다면 괜찮아요. 하지만 꺼져 있다면, 앱 주소만 아는 사람이 로그인 없이 이 테이블을 읽고 고칠 수 있어요. AI로 만든 앱에서 가장 흔한 사고 원인입니다.",
            "fix": "Supabase의 이 테이블에 RLS가 켜져 있는지 확인하고, 꺼져 있으면 켜줘. 그리고 로그인한 본인만 자기 데이터를 읽고·쓰고·지울 수 있는 정책(USING과 WITH CHECK 모두)을 만드는 SQL을 마이그레이션 파일로 추가해줘.",
        }
    if "열린 RLS 정책" in rule:
        return {
            "title": "잠금은 켰지만 열쇠가 누구에게나 맞아요",
            "what": f"보안 정책의 조건이 'true'(항상 통과)로 되어 있습니다. ({f.get('match','')})",
            "risk": "RLS를 켜도 이 정책 때문에 사실상 아무나 통과해요. 공개 게시판처럼 일부러 연 게 아니라면 남의 데이터가 보이거나 바뀔 수 있습니다.",
            "fix": "이 정책의 조건 true를 'auth.uid() = user_id'처럼 로그인한 본인 것만 허용하는 조건으로 바꿔줘. 읽기(USING)와 쓰기(WITH CHECK) 둘 다 바꿔줘.",
        }
    if "판정 불가 영역" in rule:
        return {
            "title": "밖에서는 확인할 수 없는 부분이 있어요",
            "what": f.get("note", ""),
            "risk": "이 항목들은 문제가 있다는 뜻이 아니라, 이 점검의 한계예요. 실제 사고는 여기서도 자주 나서 직접 한 번 확인해 보길 권해요.",
            "fix": "Supabase 대시보드의 Security Advisor에서 경고가 있는지 확인하고, 쓰기 정책(WITH CHECK)·rpc 함수·스토리지 버킷 권한이 '본인 것만'으로 되어 있는지 점검해줘.",
        }
    if "라이브 점검 생략" in rule:
        return {
            "title": "데이터베이스에는 직접 요청하지 않았어요",
            "what": f.get("note", ""),
            "risk": "그래서 이 결과는 코드와 설정만 보고 판단한 거예요. 실제로 잠금이 작동하는지는 Supabase 대시보드에서 확인하는 게 가장 정확해요.",
            "fix": "Supabase 대시보드 → Advisors → Security Advisor에서 경고(특히 'RLS disabled')가 있는지 확인해줘.",
        }

    # --- 공개용 키 (보이는 것이 정상) ---
    if f.get("severity") == "INFO" and ("anon key" in rule or "publishable" in rule):
        return {
            "title": "공개용 키가 보여요 (정상이에요)",
            "what": "이 키는 원래 브라우저에 공개되는 키예요. 보이는 것만으로는 문제가 되지 않아요. "
                    "데이터는 데이터 잠금(RLS) 설정이 지켜요.",
            "risk": "",
            "fix": "",
        }
    if f.get("severity") == "INFO" and "Google API key" in rule:
        return {
            "title": "Firebase 웹 키가 보여요 (정상이에요)",
            "what": "Firebase 웹 키는 앱을 구분하는 공개용 값이에요. 보이는 것만으로는 문제가 되지 않아요. "
                    "데이터는 Firestore 보안 규칙이 지켜요.",
            "risk": "",
            "fix": "",
        }

    # --- 정상(참고) ---
    if "정상" in rule or f.get("severity") == "INFO":
        return {
            "title": f.get("rule", "참고 항목"),
            "what": f.get("note", "") or f.get("match", ""),
            "risk": "이건 문제가 아니에요. 정상적으로 설정된 부분입니다.",
            "fix": "",
        }

    # 매칭 안 되면 원본을 그대로
    return {
        "title": f.get("rule", "발견 항목"),
        "what": f.get("match", ""),
        "risk": f.get("note", ""),
        "fix": "",
    }


def build_report(findings, target_name="내 앱", coverage=None, kind="repo"):
    """coverage: scanner.coverage()의 결과. 주면 '본 것과 못 본 것' 표가 들어간다."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    crit = [f for f in findings if f["severity"] == "CRITICAL"]
    warn = [f for f in findings if f["severity"] == "WARN"]
    info = [f for f in findings if f["severity"] == "INFO"]
    good = [f for f in info if info_kind(f) == "good"]
    notes = [f for f in info if info_kind(f) == "note"]
    cov = cov_counts(coverage)

    out = []
    out.append(f"# 🛡️ {target_name} 보안 점검 리포트")
    out.append(f"\n*{now} 기준 · 이 리포트는 개발 지식이 없어도 읽을 수 있게 만들어졌어요.*\n")

    # 한 줄 요약
    out.append("## 한눈에 보기\n")
    out.append(f"**{headline(crit, warn, coverage)}**\n")
    if crit:
        out.append(f"- 🔴 **지금 바로 고쳐야 할 것: {len(crit)}개**")
    if warn:
        out.append(f"- 🟡 **확인이 필요한 것: {len(warn)}개**")
    if good:
        out.append(f"- 🟢 잘 되어 있는 것: {len(good)}개")
    if cov["unknown"]:
        out.append(f"- ❓ 이번 점검으로 볼 수 없었던 영역: {cov['unknown']}개")
    out.append("")

    # 안내 문구
    if warn:
        out.append("> 🟡 '확인이 필요해요'는 **당장 뚫렸다는 뜻이 아니에요.** "
                   "밖에서는 안전한지 확실히 알 수 없어서, 한 번 확인해보길 권하는 항목입니다. "
                   "너무 걱정하지 말고 하나씩 확인해보세요.\n")

    # 점검 범위: 본 것과 못 본 것
    if coverage:
        out.append("## 이번 점검이 본 것과 못 본 것\n")
        out.append("| 영역 | 결과 | 설명 |")
        out.append("|---|---|---|")
        for r in coverage:
            icon, label = COV_META[r["status"]]
            out.append(f"| {r['label']} | {icon} {label} | {r['detail']} |")
        out.append("")
        if cov["unknown"]:
            out.append("**볼 수 없었던 영역은 이렇게 확인할 수 있어요**\n")
            for i, (key, title, body) in enumerate(next_steps(kind), 1):
                out.append(f"{i}. **{title}**: {body}")
                if key == "ai":
                    out.append(f"\n   ```\n   {SELF_CHECK_PROMPT}\n   ```")
                if key == "human" and HUMAN_CHECK_URL:
                    out.append(f"   안내: {HUMAN_CHECK_URL}")
            out.append("")

    section_titles = [
        ("CRITICAL", crit, "🔴 지금 바로 고쳐야 해요"),
        ("WARN", warn, "🟡 확인이 필요해요"),
        ("INFO", good, "🟢 잘 되어 있어요"),
        ("INFO", notes, "ℹ️ 참고 (문제 아님)"),
    ]

    n = 0
    for sev, items, header in section_titles:
        if not items:
            continue
        out.append(f"\n---\n\n## {header}\n")
        for f in items:
            t = _match_template(f)
            n += 1
            out.append(f"### {n}. {t['title']}\n")
            if t["what"]:
                out.append(f"**무엇을 발견했나요**")
                out.append(f"{t['what']}\n")
            loc = f.get("file", "")
            if loc and f.get("line"):
                loc = f"{loc}:{f['line']}"
            if loc:
                out.append(f"<sub>위치: `{loc}`</sub>\n")
            if sev != "INFO" and t["risk"]:
                out.append(f"**왜 위험한가요**")
                out.append(f"{t['risk']}\n")
            if t["fix"]:
                out.append(f"**어떻게 고치나요 — 아래를 복사해서 Cursor(또는 Lovable)에 그대로 붙여넣으세요:**")
                out.append(f"```")
                out.append(f"{t['fix']}")
                out.append(f"```\n")

    out.append("\n---\n")
    out.append("*이 리포트는 자동 점검 결과입니다. '확인이 필요해요' 항목은 실제 문제가 아닐 수도 있어요. "
               "문제를 찾지 못했다는 것이 안전하다는 뜻은 아니에요. "
               "고친 뒤 다시 점검하면 해결됐는지 확인할 수 있습니다.*")

    return "\n".join(out)


if __name__ == "__main__":
    # 데모: my-sync-todo 실제 결과를 모사한 샘플
    sample = [
        {"severity": "CRITICAL", "rule": ".env not gitignored",
         "file": "/app/.env", "line": 0, "match": ".env",
         "note": ".gitignore에 .env가 없음 → 깃에 그대로 올라가서 공개될 수 있음."},
        {"severity": "WARN", "rule": "라이브 프로빙: todos 쓰기 권한(anon POST/PATCH/DELETE)",
         "file": "", "line": 0, "match": "todos → anon POST/PATCH/DELETE GRANT",
         "note": "쓰기 정책 유무는 확인 불가. 개발자에게 INSERT/UPDATE 정책 확인 요청."},
        {"severity": "WARN", "rule": "라이브 프로빙: todos 테이블 읽기",
         "file": "https://x.supabase.co", "line": 0, "match": "todos → HTTP 200",
         "note": "200이지만 빈 배열 — RLS 있음 또는 빈 테이블 (모호)"},
        {"severity": "INFO", "rule": "클라이언트 인증 가드 (정상)",
         "file": "/app/src/routes/_authenticated/route.tsx", "line": 6,
         "match": "beforeLoad + redirect",
         "note": "화면 접근을 막는 UX 장치. 서버가 따로 막고 있으면 정상."},
    ]
    print(build_report(sample, "my-sync-todo"))
