import os, re, sys, json, base64

TARGET = sys.argv[1] if len(sys.argv) > 1 else "."
findings = []

# ---------------------------------------------------------------
# 시크릿 패턴
# ---------------------------------------------------------------
SECRET_PATTERNS = {
    "OpenAI key":        (r"sk-[A-Za-z0-9]{20,}",              "CRITICAL"),
    "Anthropic key":     (r"sk-ant-[A-Za-z0-9\-_]{20,}",       "CRITICAL"),
    "GitHub PAT":        (r"ghp_[0-9A-Za-z]{36}",              "CRITICAL"),
    "Slack token":       (r"xox[baprs]-[0-9A-Za-z\-]{10,}",    "CRITICAL"),
    "Stripe live key":   (r"sk_live_[0-9A-Za-z]{24,}",         "CRITICAL"),
    "Stripe test key":   (r"sk_test_[0-9A-Za-z]{24,}",         "WARN"),
    "Supabase secret":   (r"sb_secret_[A-Za-z0-9_\-]{20,}",    "CRITICAL"),
    "Supabase publishable": (r"sb_publishable_[A-Za-z0-9_\-]{20,}", "INFO"),
    "Google API key":    (r"AIza[0-9A-Za-z\-_]{35}",           "INFO"),
    "JWT":               (r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*", None),
}

# 오탐 방지: 이 문자열이 같은 줄에 있으면 무시
NOISE = ("example", "placeholder", "your_key", "your-key", "yourkey",
         "xxxx", "dummy", "sample", "<your", "changeme", "todo",
         "fake_key", "not_a_real", "redacted", "insert_key")

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", ".venv",
             "venv", "__pycache__", ".cache", "coverage", ".turbo"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
            ".zip", ".lock"}
MAX_BYTES = 2_000_000


def walk_files(root):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if os.path.splitext(f)[1].lower() in SKIP_EXT:
                continue
            p = os.path.join(dirpath, f)
            try:
                if os.path.getsize(p) > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield p


def redact(s):
    # Finding 생성 시점에 마스킹 — 원본 시크릿은 절대 findings에 안 들어감
    if len(s) <= 12:
        return s[:2] + "*" * (len(s) - 2)
    return s[:6] + "*" * 8 + s[-4:]


def is_noise(line):
    low = line.lower()
    return any(n in low for n in NOISE)


def looks_fake_secret(raw):
    """테스트 픽스처/더미 시크릿인지 추정. 진짜 키는 고엔트로피 랜덤."""
    tail = raw[-16:] if len(raw) >= 16 else raw
    low = raw.lower()
    # 사전식 꼬리 (WxYz, RsTu, abcd, 1234 등 연속/반복)
    if re.search(r"(?:wxyz|rstu|pqrs|qrst|abcd|efgh|ijkl|mnop|1234|0000|xxxx)", low):
        return True
    # 반복 문자 (aaaa, 1111)
    if re.search(r"(.)\1{4,}", tail):
        return True
    # 명시적 더미 표시
    if any(w in low for w in ("example", "dummy", "test123", "fake", "placeholder",
                              "sample", "your_", "changeme", "xxxxx")):
        return True
    # 연속 알파벳 시퀀스 (abcdef, qrstuv)
    seq = "abcdefghijklmnopqrstuvwxyz"
    if any(s in low for s in (seq[i:i+6] for i in range(len(seq)-5))):
        return True
    return False


def jwt_role(token):
    """Supabase JWT payload에서 role 클레임 추출. 실패하면 None."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None
    return data.get("role")


def add(severity, name, path, lineno, raw, note=""):
    findings.append({
        "severity": severity,
        "rule": name,
        "file": path,
        "line": lineno,
        "match": redact(raw),
        "note": note,
    })


# ---------------------------------------------------------------
# 탐지 #1: 시크릿
# ---------------------------------------------------------------
def detect_secrets(root):
    for path in walk_files(root):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception:
            continue

        for i, line in enumerate(lines, 1):
            if is_noise(line):
                continue
            for name, (pat, sev) in SECRET_PATTERNS.items():
                for m in re.findall(pat, line):
                    raw = m if isinstance(m, str) else m[0]

                    if name == "JWT":
                        role = jwt_role(raw)
                        if role == "service_role":
                            sig = raw.split(".")[-1] if raw.count(".") >= 2 else ""
                            # 가짜/픽스처 서명: 사전 단어, 너무 짧음, xxxx 류
                            fake_sig = (
                                len(sig) < 20
                                or re.fullmatch(r"[a-p]+", sig or "")          # abcdefgh...
                                or "signature" in sig.lower()
                                or "xxx" in sig.lower()
                                or "fixture" in raw.lower()
                            )
                            low = path.lower()
                            is_test = any(k in low for k in
                                          ("test", "spec", "fixture", "mock", "example", "sample", "__tests__"))
                            if fake_sig:
                                pass  # 가짜 서명 = 픽스처, 보고 안 함
                            elif is_test:
                                add("WARN", "테스트 파일에 service_role 키(확인 필요)", path, i, raw,
                                    "테스트/스크립트 파일에 마스터키가 있습니다. 픽스처면 괜찮지만, 진짜 키라면 실제로 노출된 것이니 확인하세요.")
                            else:
                                add("CRITICAL", "Supabase service_role key", path, i, raw,
                                    "클라이언트에 있으면 DB 전체가 뚫림. RLS를 통째로 우회함. (변수명이 anon이어도 실제 role은 service_role일 수 있으니 주의)")
                        elif role == "anon":
                            add("INFO", "Supabase anon key", path, i, raw,
                                "공개용 키라 노출 자체는 정상. 단, RLS가 켜져 있어야 안전 (탐지 #2에서 확인).")
                        continue

                    if name == "Stripe live key":
                        raw = "sk_live_" + raw if not raw.startswith("sk_live_") else raw
                    if name == "Stripe test key":
                        raw = "sk_test_" + raw if not raw.startswith("sk_test_") else raw

                    # 가짜/픽스처 시크릿 필터 (Google 키는 public-by-design이라 제외)
                    if name != "Google API key" and sev == "CRITICAL":
                        low_path = path.lower()
                        is_test = any(k in low_path for k in
                                      ("test", "spec", "fixture", "mock", "example", "sample",
                                       "__tests__", "scanner", "audit", "secret-scan"))
                        if looks_fake_secret(raw):
                            continue  # 명백한 더미 → 보고 안 함
                        if is_test:
                            add("WARN", f"테스트 파일에 {name}(확인 필요)", path, i, raw,
                                "테스트/스캐너 파일에 키가 있습니다. 픽스처면 괜찮지만, 진짜 키라면 노출된 것이니 확인하세요.")
                            continue

                    note = ""
                    if name == "Google API key":
                        note = "Firebase 웹 API 키는 public-by-design 식별자. 노출 자체는 취약점 아님 (Firestore 규칙이 진짜 관건)."
                    add(sev, name, path, i, raw, note)


# ---------------------------------------------------------------
# 탐지 #1-b: .env 가 .gitignore 에 없음
# ---------------------------------------------------------------
def detect_env_tracked(root):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        envs = [f for f in files if f == ".env" or f.startswith(".env.")]
        envs = [f for f in envs if not f.endswith(".example") and not f.endswith(".sample")]
        if not envs:
            continue
        gi = os.path.join(dirpath, ".gitignore")
        ignored = ""
        if os.path.exists(gi):
            ignored = open(gi, encoding="utf-8", errors="ignore").read()
        for e in envs:
            if ".env" not in ignored:
                findings.append({
                    "severity": "CRITICAL",
                    "rule": ".env not gitignored",
                    "file": os.path.join(dirpath, e),
                    "line": 0,
                    "match": e,
                    "note": ".gitignore에 .env가 없음 → 깃에 그대로 올라가서 공개될 수 있음.",
                })


# ---------------------------------------------------------------
# 탐지 #2, #3 은 여기 이어서 (9/2, 9/3)
# ---------------------------------------------------------------

# ---------------------------------------------------------------
# 탐지 #3: 서버 함수 인증 미들웨어 / 소유권 검증 누락
#   - createServerFn 있는데 인증 미들웨어 없음 -> 무방비
#   - from(table).select/update/delete 하는데 소유권 필터 없음 -> IDOR 의심
#   ※ 클라이언트 인증 가드(beforeLoad + redirect)만 있는 건 취약 신호가 아님 (오탐 트랩)
# ---------------------------------------------------------------
# 서버 함수/핸들러 진입점 (프레임워크별)
SERVER_FN_RE   = re.compile(r"createServerFn\s*\(")
# next-connect / Express / router 의 쓰기 핸들러
HANDLER_RE     = re.compile(
    r"\b(?:handler|app|router)\s*\.\s*(?:post|put|patch|delete)\s*\("
)
# Next.js App Router 라우트 핸들러
NEXT_ROUTE_RE  = re.compile(
    r"export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b"
)
# 인증 미들웨어/검사 흔적 (프레임워크 무관하게 넓게)
AUTH_MW_RE     = re.compile(
    r"require\w*[Aa]uth|\.middleware\s*\(\s*\[[^\]]*[Aa]uth"
    r"|getUser\s*\(|getSession\s*\(|auth\.getUser|getServerSession"
    r"|getToken\s*\(|currentUser\s*\(|\bauth\s*\(\s*\)"          # next-auth getToken / clerk currentUser / auth()
    r"|verifyToken|verifyJwt|jwt\.verify|requireUser|authenticate\b"
    r"|clerkClient|@clerk|withApiAuth|getAuth\s*\("            # clerk 계열
    r"|req\.user\b|session\.user\b|ctx\.user\b|locals\.user\b"
    r"|token\?\.\w|token\.email|token\.sub",                   # 토큰 클레임 검사 흔적
    re.I,
)
# 서버 코드에서 사용자 식별의 신뢰 가능한 출처
TRUSTED_UID_RE = re.compile(r"context\.userId|context\.user\b|auth\.getUser|getUser\s*\(")
# 소유권 필터: .eq('user_id'/'owner'...) 또는 .match({ user_id / owner: ... })
#   ※ id 로만 거르는 건 소유권 아님 (남의 id 를 넣으면 그대로 뚫림)
OWNER_FILTER_RE = re.compile(
    r"\.eq\s*\(\s*['\"](?:user_id|owner_id|owner|author_id|created_by|profile_id)['\"]"
    r"|\.match\s*\(\s*\{[^}]*\b(?:user_id|owner_id|owner|author_id|created_by|profile_id)\b"
    r"|\.filter\s*\(\s*['\"](?:user_id|owner_id|owner)['\"]"
)
# 쓰기/읽기 쿼리
WRITE_QUERY_RE = re.compile(r"\.from\s*\(\s*['\"](\w+)['\"]\s*\)[\s\S]{0,120}?\.(insert|update|delete)\b")
READ_QUERY_RE  = re.compile(r"\.from\s*\(\s*['\"](\w+)['\"]\s*\)[\s\S]{0,120}?\.(select)\b")

# 클라이언트 전용 인증 가드 (오탐 트랩 — 이것만으로는 취약 아님)
CLIENT_GUARD_RE = re.compile(r"beforeLoad[\s\S]{0,200}?redirect\s*\(")

SERVER_HINT_DIRS = ("/api/", "server", "functions", "/lib/", ".server.")
CLIENT_EXT = (".tsx", ".ts", ".jsx", ".js")

# RLS를 우회하는 클라이언트 = service_role 키로 만든 admin 클라이언트
#   이게 있어야 소유권 필터 부재가 진짜 IDOR이 됨 (RLS가 꺼지니까)
RLS_BYPASS_RE = re.compile(
    r"service_role|SERVICE_ROLE|serviceRole"
    r"|createClient\s*\([^)]*SERVICE"
    r"|supabaseAdmin|adminClient|createAdminClient"
    r"|\.auth\.admin\b"
)

# 클라이언트 코드 신호 (React 훅, 브라우저 API) — 이게 있으면 서버 아님
CLIENT_HINT_RE = re.compile(
    r"useQuery|useMutation|useEffect|useState|from\s+['\"]react['\"]"
    r"|@tanstack/react-query|'use client'|\"use client\""
)


def looks_server(path, text):
    """서버 실행 코드인지 추정. 클라이언트 신호가 강하면 False."""
    # 명백한 서버 신호
    server_sig = (
        "createServerFn" in text
        or ".server." in path
        or "/api/" in path
        or "/functions/" in path
        or "/server/" in path
        or "next-connect" in text
    )
    if not server_sig:
        return False
    # 서버 경로에 있어도 React 훅 파일이면 클라이언트로 간주 (오탐 주원인)
    if CLIENT_HINT_RE.search(text):
        return False
    return True


def bypasses_rls(text):
    """이 코드가 RLS를 우회하는 맥락인가 (service_role/admin 클라이언트)."""
    return bool(RLS_BYPASS_RE.search(text))


# 서버에서 도는 파일인가 — '잘 된 점'과 점검 범위 표가 쓰는 판정.
#   looks_server()보다 넓다: Next.js 라우트·서버 액션·SvelteKit 엔드포인트도 서버로 본다.
#   React 훅이 있는 화면 파일은 서버가 아니다. 화면 코드의 getUser()는 '뒷문을 지킨다'는 근거가 못 된다.
SERVER_PATH_HINTS = ("/api/", "/functions/", "/server/", ".server.", "+server.", "/middleware.")


def is_server_file(path, text):
    p = path.replace(os.sep, "/")
    sig = (
        any(h in p for h in SERVER_PATH_HINTS)
        or "createServerFn" in text
        or "next-connect" in text
        or bool(NEXT_ROUTE_RE.search(text))
        or "'use server'" in text or '"use server"' in text
    )
    return bool(sig) and not CLIENT_HINT_RE.search(text)


def detect_authz(root):
    for path in walk_files(root):
        if os.path.splitext(path)[1] not in CLIENT_EXT:
            continue
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue

        has_server_fn = bool(SERVER_FN_RE.search(text))
        has_handler   = bool(HANDLER_RE.search(text)) or bool(NEXT_ROUTE_RE.search(text))
        has_auth_mw   = bool(AUTH_MW_RE.search(text))
        has_trusted   = bool(TRUSTED_UID_RE.search(text))
        does_db_write = bool(WRITE_QUERY_RE.search(text))
        is_client     = bool(CLIENT_HINT_RE.search(text))

        # (1) 서버 쓰기 엔드포인트인데 인증 흔적이 전혀 없음 -> 무방비
        #     프레임워크: TanStack createServerFn / next-connect·Express handler / Next.js route
        #     조건: 쓰기 엔드포인트 + DB 쓰기 수행 + 인증 흔적 없음 + 클라 파일 아님
        server_entry = has_server_fn or (has_handler and (looks_server(path, text) or "/api/" in path))
        if server_entry and does_db_write and not has_auth_mw and not has_trusted and not is_client:
            if has_server_fn:
                where, kind = _line_of(text, SERVER_FN_RE), "createServerFn(...)"
            elif NEXT_ROUTE_RE.search(text):
                where, kind = _line_of(text, NEXT_ROUTE_RE), "export async function POST/PUT/DELETE"
            else:
                where, kind = _line_of(text, HANDLER_RE), "handler/app/router.post(...)"

            # admin/dashboard 등 명백히 보호돼야 할 경로 → CRITICAL
            # 그 외(공개 폼일 수 있음: contact/subscribe/feedback 등) → WARN
            low = path.lower()
            is_admin_path = any(k in low for k in ("/admin", "admin/", "dashboard", "/manage", "internal"))
            is_public_form = any(k in low for k in ("contact", "subscribe", "newsletter",
                                                    "feedback", "waitlist", "signup", "register", "webhook"))
            captcha = bool(re.search(r"recaptcha|hcaptcha|captchaToken|turnstile", text, re.I))

            if is_admin_path:
                findings.append({
                    "severity": "CRITICAL", "rule": "관리자 기능에 인증 없음",
                    "file": path, "line": where, "match": kind,
                    "note": "관리자용으로 보이는 서버 기능에 로그인 확인이 없습니다. 아무나 이 기능을 직접 호출할 수 있어요. 반드시 인증을 추가하세요.",
                })
            else:
                hint = ""
                if is_public_form or captcha:
                    hint = " (연락처·구독 같은 공개 폼이면 로그인이 없는 게 정상일 수 있어요.)"
                findings.append({
                    "severity": "WARN", "rule": "서버 함수 인증 없음(확인 필요)",
                    "file": path, "line": where, "match": kind,
                    "note": "데이터를 바꾸는 서버 기능에 로그인 확인이 안 보입니다." + hint +
                            " 로그인한 사용자만 써야 하는 기능이라면 인증을 추가하세요.",
                })

        # (2) IDOR: 서버 코드 + RLS 우회(service_role) + 소유권 필터 없음
        #     ※ 쿼리마다 세면 파일 하나에서 수백 건 터짐 → 파일당 1건으로 접음.
        #     정적 분석의 한계: admin 함수가 소유권을 안 챙기는 게 버그인지
        #     웹훅처럼 원래 그런 건지 코드만으론 확정 불가 → "확인 필요"로만.
        if looks_server(path, text) and bypasses_rls(text):
            unfiltered = []
            seen = set()
            for m in list(WRITE_QUERY_RE.finditer(text)) + list(READ_QUERY_RE.finditer(text)):
                tbl, op = m.group(1), m.group(2)
                lineno = text[:m.start()].count("\n") + 1
                if (lineno, op) in seen:
                    continue
                seen.add((lineno, op))
                near = text[max(0, m.start()-40):m.end()+200]
                if op == "insert":
                    if re.search(r"user_id\s*:|owner\w*\s*:", near):
                        continue
                else:
                    if OWNER_FILTER_RE.search(near):
                        continue
                    if op == "select" and re.search(r"\.(insert|update)\s*\([\s\S]{0,200}?\.select", near):
                        continue
                unfiltered.append((tbl, op, lineno))

            if unfiltered:
                tables = sorted(set(t for t, _, _ in unfiltered))
                first_line = min(l for _, _, l in unfiltered)
                findings.append({
                    "severity": "WARN", "rule": "관리자 권한 코드에 소유권 검증 없음(IDOR 의심)",
                    "file": path, "line": first_line,
                    "match": f"admin(service_role) 권한으로 {len(unfiltered)}개 쿼리, 소유권 조건 안 보임 (테이블: {', '.join(tables[:5])})",
                    "note": "이 서버 코드는 모든 보안 잠금을 무시하는 관리자 권한으로 돕니다. '본인 것만' 거르는 조건이 안 보여요. 다만 외부 웹훅처럼 원래 전체를 봐야 하는 코드일 수도 있어, 개발자에게 '이 함수가 사용자별로 걸러야 하는지' 확인을 권합니다.",
                })

        # (3) 오탐 트랩 기록용: 클라 인증 가드만 있는 경우 — 취약으로 세지 않음
        if CLIENT_GUARD_RE.search(text) and not has_server_fn:
            findings.append({
                "severity": "INFO", "rule": "클라이언트 인증 가드 (정상)",
                "file": path, "line": _line_of(text, CLIENT_GUARD_RE),
                "match": "beforeLoad + redirect",
                "note": "화면 접근을 막는 UX 장치. 서버가 따로 막고 있으면 정상. 이것만으로 취약하지 않음.",
            })


def _line_of(text, rx):
    m = rx.search(text)
    return text[:m.start()].count("\n") + 1 if m else 0


# 긍정 신호 패턴 (안전하게 잘 된 것)
RLS_ENABLE_RE  = re.compile(r"enable\s+row\s+level\s+security|ENABLE\s+ROW\s+LEVEL", re.I)
RLS_POLICY_RE  = re.compile(r"create\s+policy", re.I)
GITIGNORE_ENV_RE = re.compile(r"^\s*\.env", re.M)


def detect_good_signals(root, kind="repo"):
    """안전하게 잘 된 점을 앱 전체에서 한 번씩 집계 → INFO.
    '정상 0'으로 나와 신뢰가 안 가는 문제(약점 ③) 해결.

    사이트 진단(kind="site")에서는 아무것도 내지 않는다. 받은 것이 화면 코드(번들)뿐이라
    supabase-js 라이브러리 안의 getUser() 같은 것까지 '서버가 로그인을 확인한다'로 읽히기 때문."""
    if kind == "site":
        return
    has_rls_enable = False
    has_rls_policy = False
    has_server_auth = False
    has_owner_filter = False
    env_gitignored = False
    env_exists = False

    for path in walk_files(root):
        ext = os.path.splitext(path)[1]
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue

        if ext == ".sql" or "migration" in path.lower():
            if RLS_ENABLE_RE.search(text):
                has_rls_enable = True
            if RLS_POLICY_RE.search(text):
                has_rls_policy = True
        # SQL은 .ts/.js 안에 문자열로도 들어감 (README 같은 문서의 문장은 설정이 아니므로 세지 않음)
        if ext in CLIENT_EXT:
            if RLS_ENABLE_RE.search(text):
                has_rls_enable = True
            if RLS_POLICY_RE.search(text):
                has_rls_policy = True
        # 서버 인증·소유자 조건은 서버에서 도는 파일에 있을 때만 '잘 된 점'이다
        if ext in CLIENT_EXT and is_server_file(path, text):
            if AUTH_MW_RE.search(text) or TRUSTED_UID_RE.search(text):
                has_server_auth = True
            if OWNER_FILTER_RE.search(text):
                has_owner_filter = True

    # .gitignore에 .env 있는지
    gi = os.path.join(root, ".gitignore")
    if os.path.exists(gi):
        try:
            if GITIGNORE_ENV_RE.search(open(gi, encoding="utf-8", errors="ignore").read()):
                env_gitignored = True
        except Exception:
            pass

    goods = []
    if has_rls_enable:
        goods.append(("RLS(행 보안)가 켜져 있어요",
                      "데이터베이스에 Row Level Security를 켜는 설정이 있습니다. 로그인한 본인 데이터만 보이게 하는 핵심 잠금이에요."))
    if has_rls_policy:
        goods.append(("접근 정책이 설정돼 있어요",
                      "누가 무엇을 볼 수 있는지 정하는 정책(policy)이 코드에 있습니다. 잘 챙긴 부분이에요."))
    if has_server_auth:
        goods.append(("서버에서 로그인을 확인해요",
                      "서버 기능에 로그인 확인(인증)이 있습니다. 화면뿐 아니라 뒷문도 지키고 있어요."))
    if has_owner_filter:
        goods.append(("본인 데이터만 거르는 조건이 있어요",
                      "쿼리에 '내 것만' 걸러내는 조건(user_id 등)이 보입니다. 남의 데이터 접근을 막는 좋은 습관이에요."))
    if env_gitignored:
        goods.append((".env가 깃에서 제외돼 있어요",
                      ".gitignore에 .env가 들어 있어 비밀 설정이 깃허브에 안 올라갑니다. 잘 돼 있어요."))

    for title, note in goods:
        findings.append({
            "severity": "INFO", "rule": f"잘 된 점: {title}",
            "file": "", "line": 0, "match": "",
            "note": note,
        })


# ---------------------------------------------------------------
# 탐지 #4: 마이그레이션 SQL로 RLS 정적 판정 (DB에 요청 안 보냄)
#   Supabase Security Advisor 린트와 같은 기준:
#   0013 rls_disabled_in_public / 0024 permissive_rls_policy
# ---------------------------------------------------------------
SQL_CREATE_TABLE_RE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?(\w+)\"?\.)?\"?(\w+)\"?", re.I)
SQL_ENABLE_RLS_RE = re.compile(
    r"alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:\"?(\w+)\"?\.)?\"?(\w+)\"?\s+enable\s+row\s+level\s+security", re.I)
SQL_POLICY_RE = re.compile(
    r"create\s+policy\s+(\"[^\"]+\"|\w+)\s+on\s+(?:\"?(\w+)\"?\.)?\"?(\w+)\"?([\s\S]*?);", re.I)
SUPABASE_HINT_RE = re.compile(r"@supabase/supabase-js|createClient\s*\(|supabase\.co", re.I)


def detect_migrations(root):
    created, enabled, open_policies = {}, set(), []
    uses_supabase = os.path.isdir(os.path.join(root, "supabase"))
    for path in walk_files(root):
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        if not uses_supabase and os.path.splitext(path)[1] in CLIENT_EXT and SUPABASE_HINT_RE.search(text):
            uses_supabase = True
        if not path.endswith(".sql"):
            continue
        for m in SQL_CREATE_TABLE_RE.finditer(text):
            if (m.group(1) or "public").lower() == "public":
                created.setdefault(m.group(2), (path, text[:m.start()].count("\n") + 1))
        for m in SQL_ENABLE_RLS_RE.finditer(text):
            if (m.group(1) or "public").lower() == "public":
                enabled.add(m.group(2))
        for m in SQL_POLICY_RE.finditer(text):
            body = m.group(4)
            cmd = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", body, re.I)
            if re.search(r"\b(using|with\s+check)\s*\(\s*true\s*\)", body, re.I):
                open_policies.append((m.group(3), (cmd.group(1).upper() if cmd else "ALL"),
                                      path, text[:m.start()].count("\n") + 1, m.group(1)))

    # Supabase 앱이 아니면(예: 자체 Postgres + drizzle) RLS 기준을 적용하지 않음
    if not uses_supabase:
        return
    for tbl, (path, line) in sorted(created.items()):
        if tbl not in enabled:
            findings.append({
                "severity": "WARN", "rule": "마이그레이션: RLS 꺼진 테이블(확인 필요)",
                "file": path, "line": line, "match": f"create table {tbl} — enable row level security 없음",
                "note": "SQL로 만든 테이블에 RLS를 켜는 줄이 코드에 없습니다. 대시보드에서 따로 켰을 수도 있지만, "
                        "꺼져 있다면 공개 키만으로 누구나 이 테이블을 읽고 쓸 수 있어요.",
            })
    for tbl, cmd, path, line, name in open_policies:
        findings.append({
            "severity": "WARN", "rule": "마이그레이션: 누구에게나 열린 RLS 정책(확인 필요)",
            "file": path, "line": line, "match": f"policy {name} on {tbl} ({cmd}) — using/with check (true)",
            "note": "조건이 true인 정책은 RLS를 켜도 사실상 잠금이 없는 것과 같아요. "
                    "공개 게시판처럼 일부러 연 게 아니라면 '본인 것만' 조건으로 바꾸세요.",
        })


# ---------------------------------------------------------------
# 점검 범위: 이번 점검이 '볼 수 있었던 것'과 '볼 수 없었던 것'
#   문제를 못 찾은 것과 아예 보지 못한 것은 다르다. 리포트가 못 본 영역을 초록으로 칠하지 않게
#   영역마다 상태를 따로 적는다. (Hacker Safe 2008: 스캔 통과 표시를 단 사이트에서 XSS가 나온 사례)
# ---------------------------------------------------------------
AREAS = [
    ("secret", "비밀 키 노출"),
    ("env",    "비밀 설정 파일(.env) 관리"),
    ("rls",    "데이터 잠금(RLS) 설정"),
    ("auth",   "서버 기능의 로그인 확인"),
    ("owner",  "남의 데이터 접근 차단(본인 것만)"),
    ("live",   "실제로 막히는지(밖에서 요청해 보기)"),
]
# 점검 범위용 Supabase 판별. createClient( 는 다른 라이브러리도 쓰는 이름이라 여기서는 뺀다.
SUPABASE_FACT_RE = re.compile(
    r"@supabase/|supabase-js|supabase\.co\b|lovable\.cloud|sb_publishable_|sb_secret_|SUPABASE_URL")
FIREBASE_FACT_RE = re.compile(r"firebaseConfig|firebase/app|firebaseapp\.com|firestore", re.I)

FACTS = {}   # 마지막 run()이 본 재료. coverage()가 읽는다.


def collect_facts(root, kind="repo"):
    """점검 범위 표의 재료. 무엇을 '볼 수 있었는지'만 센다(판정은 하지 않는다)."""
    facts = {"kind": kind, "files": 0, "sql_tables": 0, "server_files": 0, "admin_files": 0,
             "supabase": os.path.isdir(os.path.join(root, "supabase")), "firebase": False}
    for path in walk_files(root):
        facts["files"] += 1
        ext = os.path.splitext(path)[1].lower()
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        if ext in CLIENT_EXT or ext in (".mjs", ".html") or os.path.basename(path).startswith(".env"):
            if SUPABASE_FACT_RE.search(text):
                facts["supabase"] = True
            if FIREBASE_FACT_RE.search(text):
                facts["firebase"] = True
        if ext == ".sql":
            facts["sql_tables"] += sum(1 for m in SQL_CREATE_TABLE_RE.finditer(text)
                                       if (m.group(1) or "public").lower() == "public")
        # 사이트 진단은 화면 코드만 받는다 → 서버 파일은 세지 않는다
        if kind != "site" and ext in CLIENT_EXT and is_server_file(path, text):
            facts["server_files"] += 1
            if bypasses_rls(text):
                facts["admin_files"] += 1
    return facts


def area_of(f):
    """위험 항목이 어느 점검 영역에 속하는지."""
    r = f.get("rule", "")
    if "라이브" in r:
        return "live"
    if "마이그레이션" in r:
        return "rls"
    if ".env not gitignored" in r:
        return "env"
    if "소유권" in r or "IDOR" in r:
        return "owner"
    if "인증 없음" in r:
        return "auth"
    return "secret"      # 남는 위험 항목은 전부 키 노출 계열


def coverage(found, facts, live=False):
    """영역별 상태 목록. status: ok(확인함·문제 못 찾음) / issue(확인함·살펴볼 것 있음)
    / unknown(확인 못 함) / na(해당 없음). live는 실제로 읽기 요청을 보냈을 때만 True."""
    if not facts:
        return []
    site = facts["kind"] == "site"
    risky = set(area_of(f) for f in found if f["severity"] in ("CRITICAL", "WARN"))
    n = facts["files"]
    row = {}

    row["secret"] = ("ok", f"브라우저가 내려받는 화면 코드 {n}개 파일에서 비밀 키 모양을 찾아봤어요." if site else
                     f"저장소 파일 {n}개에서 비밀 키 모양을 찾아봤어요. 지난 커밋 기록은 보지 않았어요.")

    if site:
        row["env"] = ("unknown", "앱 주소만으로는 저장소 설정을 볼 수 없어요. GitHub 주소로 점검하면 확인돼요.")
        row["rls"] = ("unknown", "잠금 설정은 데이터베이스 안에 있어서 화면 코드에는 보이지 않아요. "
                                 "가장 흔한 사고 원인인데 이 점검으로는 알 수 없었어요.")
        row["auth"] = ("unknown", "서버에서 도는 코드는 밖에서 받아 볼 수 없어요.")
        row["owner"] = ("unknown", "서버 코드를 볼 수 없어서 확인하지 못했어요.")
    else:
        row["env"] = ("ok", ".env 파일이 깃에 올라가지 않게 .gitignore에 들어 있는지 봤어요.")
        if facts["supabase"] and facts["sql_tables"]:
            row["rls"] = ("ok", f"테이블을 만드는 SQL에서 {facts['sql_tables']}개 테이블의 잠금 설정을 읽었어요. "
                                "코드에 적힌 내용 기준이라, 실제 데이터베이스가 코드와 같은지는 따로 확인이 필요해요.")
        elif facts["supabase"]:
            row["rls"] = ("unknown", "Supabase를 쓰는데 테이블을 만드는 SQL 파일이 저장소에 없어요. "
                                     "대시보드에서 만든 테이블의 잠금은 코드에 남지 않아 확인하지 못했어요.")
        elif facts["firebase"]:
            row["rls"] = ("unknown", "Firebase 규칙은 아직 점검하지 못해요.")
        else:
            row["rls"] = ("na", "Supabase·Firebase를 쓰는 흔적이 없어요. 데이터베이스가 없는 앱이면 해당 없고, "
                                "다른 데이터베이스를 쓴다면 이 점검 범위 밖이에요.")
        if facts["server_files"]:
            row["auth"] = ("ok", f"서버에서 도는 코드 {facts['server_files']}개 파일을 살펴봤어요. "
                                 "다른 파일에서 한꺼번에 로그인을 확인하는 구조는 놓칠 수 있어요.")
        else:
            row["auth"] = ("na", "서버에서 도는 코드를 찾지 못했어요. 화면만 있고 데이터는 데이터베이스 잠금이 지키는 앱이면 정상이에요.")
        if facts["admin_files"]:
            row["owner"] = ("ok", f"모든 잠금을 건너뛰는 관리자 권한 코드 {facts['admin_files']}개 파일에서 "
                                  "'본인 것만' 조건을 찾아봤어요.")
        else:
            row["owner"] = ("na", "모든 잠금을 건너뛰는 관리자 권한 코드는 없었어요. 이 경우 '본인 것만'은 데이터 잠금(RLS)이 맡아요.")

    if live:
        row["live"] = ("ok", "로그인 없이 읽기 요청을 테이블마다 1건씩 보내 봤어요. "
                             "쓰기 정책, rpc 함수, 스토리지는 이 방법으로 알 수 없어요.")
    else:
        row["live"] = ("unknown", "이번 점검은 앱의 데이터베이스에 요청을 보내지 않았어요. 주인이 확인된 앱에만 보내기 때문이에요. "
                                  "그래서 실제로 막히는지는 알 수 없어요.")

    out = []
    for key, label in AREAS:
        status, detail = row[key]
        if key in risky:            # 위험 항목이 나온 영역은 어떤 경우든 '살펴볼 것 있음'
            status = "issue"
        out.append({"key": key, "label": label, "status": status, "detail": detail})
    return out


def run(target, kind="repo"):
    """정적 분석 실행 → findings 리스트 반환 (실행기에서 import용).
    kind="site"는 배포 주소에서 받은 화면 코드(번들)라는 뜻. 저장소·서버 코드가 있어야 의미가 있는
    검사(.gitignore, 서버 인증, 마이그레이션)는 돌리지 않는다. 번들에서 돌리면 거짓 결과만 나온다."""
    global findings, FACTS
    findings = []
    detect_secrets(target)
    if kind != "site":
        detect_env_tracked(target)
        detect_authz(target)
        detect_migrations(target)
    detect_good_signals(target, kind)
    FACTS = collect_facts(target, kind)
    ORDER = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
    findings.sort(key=lambda f: (ORDER.get(f["severity"], 9), f["file"], f["line"]))
    return findings


ICON = {"CRITICAL": "[!!]", "WARN": "[? ]", "INFO": "[ok]"}


def _print_report(items, target):
    print(f"\n=== Vibe Coding Scanner (정적) === target: {os.path.abspath(target)}\n")
    if not items:
        print("발견된 항목 없음.\n")
    for f in items:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        print(f"{ICON.get(f['severity'],'[  ]')} {f['severity']:8} {f['rule']}")
        print(f"     {loc}")
        print(f"     {f['match']}")
        if f["note"]:
            print(f"     -> {f['note']}")
        print()
    c = sum(1 for f in items if f["severity"] == "CRITICAL")
    w = sum(1 for f in items if f["severity"] == "WARN")
    i = sum(1 for f in items if f["severity"] == "INFO")
    print(f"--- 치명적 {c} / 확인필요 {w} / 정상 {i} ---\n")


if __name__ == "__main__":
    _print_report(run(TARGET), TARGET)
