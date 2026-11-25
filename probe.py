import os, re, sys, json, base64
import requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "."
CAPTURE_DIR = "probe_fixtures"
# 기본은 끔 — 남의 앱 응답 원본(실데이터)을 디스크에 남기지 않기 위해.
# 본인 앱의 오프라인 개발용 자료가 필요할 때만 `python probe.py <폴더> --capture`로 켠다.
CAPTURE_ENABLED = False

SKIP_DIRS = {"node_modules", ".git", ".next", ".venv", "venv", "__pycache__"}

URL_RE = re.compile(r"https://[A-Za-z0-9\-\.]+\.(?:supabase\.co|lovable\.cloud)")
REF_RE = re.compile(r"\b[a-z]{20}\b")
NEWKEY_RE = re.compile(r"sb_publishable_[A-Za-z0-9_\-]{20,}")
SECRETKEY_RE = re.compile(r"sb_secret_[A-Za-z0-9_\-]{20,}")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")


def jwt_role(token):
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p)).get("role")
    except Exception:
        return None


def classify_key(k):
    """새 포맷 접두사 우선, 레거시는 JWT payload 디코딩."""
    if k.startswith("sb_secret_"):
        return "secret"
    if k.startswith("sb_publishable_"):
        return "publishable"
    r = jwt_role(k)
    if r == "service_role":
        return "secret"
    if r == "anon":
        return "publishable"
    return "unknown"


# ---------------------------------------------------------------
# 설정값 추출: .env -> 소스 리터럴 -> 빌드 번들 순으로 폴백
# ---------------------------------------------------------------
def _scan_text(text):
    urls = set(URL_RE.findall(text))
    keys = set(NEWKEY_RE.findall(text)) | set(JWT_RE.findall(text))
    secrets = set(SECRETKEY_RE.findall(text))
    return urls, keys, secrets


def find_config(root):
    urls, keys, secrets, refs, src = set(), set(), set(), set(), None

    def read(p):
        try:
            return open(p, encoding="utf-8", errors="ignore").read()
        except Exception:
            return ""

    # 1) .env
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.startswith(".env") and not f.endswith((".example", ".sample")):
                t = read(os.path.join(dp, f))
                u, k, s = _scan_text(t)
                if u or k:
                    src = src or ".env"
                urls |= u; keys |= k; secrets |= s
                for line in t.splitlines():
                    if "PROJECT_ID" in line:
                        refs |= set(REF_RE.findall(line))

    # 2) 소스 리터럴 + 3) 빌드 번들
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if not f.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".html")):
                continue
            t = read(os.path.join(dp, f))
            u, k, s = _scan_text(t)
            if (u or k) and not src:
                src = "bundle" if ("dist" in dp or "assets" in dp) else "source"
            urls |= u; keys |= k; secrets |= s

    # Lovable Cloud 프록시 -> 직결 supabase.co 엔드포인트 추가
    for r in refs:
        urls.add(f"https://{r}.supabase.co")

    pub = [k for k in keys if classify_key(k) == "publishable"]
    sec = [k for k in keys if classify_key(k) == "secret"] + list(secrets)
    return {"urls": sorted(urls), "publishable": pub, "secret": sec, "source": src}


# ---------------------------------------------------------------
# 테이블명 추출: 2026-04-08부터 anon 키로는 /rest/v1/ OpenAPI(테이블 목록)가 막힘
#   → 코드의 supabase.from('테이블') 호출과 마이그레이션 SQL의 CREATE TABLE에서 직접 뽑는다
#   https://supabase.com/changelog/42949-breaking-change-removing-access-to-openapi-spec-via-the-anon-key
# ---------------------------------------------------------------
FROM_CALL_RE = re.compile(r"""(storage\s*)?\.from\(\s*['"`]([A-Za-z_]\w*)['"`]\s*\)""")
CREATE_TABLE_RE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?(\w+)\"?\.)?\"?(\w+)\"?", re.I)


def extract_tables(root):
    tables = set()
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            p = os.path.join(dp, f)
            if f.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs")):
                try:
                    t = open(p, encoding="utf-8", errors="ignore").read()
                except Exception:
                    continue
                for storage, name in FROM_CALL_RE.findall(t):
                    if not storage:            # supabase.storage.from('버킷')은 테이블 아님
                        tables.add(name)
            elif f.endswith(".sql"):
                try:
                    t = open(p, encoding="utf-8", errors="ignore").read()
                except Exception:
                    continue
                for schema, name in CREATE_TABLE_RE.findall(t):
                    if (schema or "public").lower() == "public":
                        tables.add(name)
    return sorted(tables)


# ---------------------------------------------------------------
# 라이브 프로빙 (읽기 GET 만)
# ---------------------------------------------------------------
HEADER_MODES = [
    ("apikey + Bearer", lambda k: {"apikey": k, "Authorization": f"Bearer {k}"}),
    ("apikey only",     lambda k: {"apikey": k}),
    ("Bearer only",     lambda k: {"Authorization": f"Bearer {k}"}),
]

WORKING_MODE = {}   # 통한 조합을 기억해서 이후 요청에 재사용


def headers_for(key):
    if WORKING_MODE.get("fn"):
        return WORKING_MODE["fn"](key)
    return HEADER_MODES[0][1](key)


def negotiate(base, key):
    """어떤 헤더 조합이 통하는지 찾는다. 조합마다 응답을 따로 캡처."""
    first = None
    for idx, (name, fn) in enumerate(HEADER_MODES):
        try:
            r = requests.get(f"{base}/rest/v1/", headers=fn(key), timeout=15)
        except Exception as e:
            print(f"    헤더 조합 '{name}' -> 요청 실패: {e}")
            continue
        capture(f"openapi_mode{idx}", r)
        if first is None:
            first = r
        if r.status_code == 200:
            WORKING_MODE["name"] = name
            WORKING_MODE["fn"] = fn
            capture("openapi", r)
            print(f"    헤더 조합: {name}  -> 200 (사용)")
            return r
        msg = r.text[:160].replace("\n", " ")
        print(f"    헤더 조합 '{name}' -> {r.status_code}  {msg}")
    if first is not None:
        capture("openapi", first)
    return first


def capture(name, resp):
    if not CAPTURE_ENABLED:
        return
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    body = resp.text[:20000]
    with open(os.path.join(CAPTURE_DIR, name + ".json"), "w") as fh:
        json.dump({"url": resp.url, "status": resp.status_code,
                   "headers": dict(resp.headers), "body": body}, fh,
                  indent=2, ensure_ascii=False)


WRITE_VERBS = ("post", "patch", "delete", "put")

# 이름만 봐도 민감한 컬럼
SENSITIVE_COLS = ("email", "phone", "address", "ssn", "birth", "password",
                  "token", "secret", "card", "account", "salary", "income",
                  "national_id", "resident")

TABLE_VERBS = {}      # 테이블 -> 허용된 쓰기 동사
TABLE_COLS = {}       # 테이블 -> 컬럼 목록
FINGERPRINT = {}


def list_tables(base, key):
    r = negotiate(base, key)
    if r is None:
        return [], 0
    capture("openapi", r)

    # 지문: 프록시 뒤의 진짜 프로젝트 ref (URL만 아는 남의 앱에서 유용)
    if r.headers.get("sb-project-ref"):
        FINGERPRINT["ref"] = r.headers["sb-project-ref"]
    if r.headers.get("X-Lovable-Cloud-Proxy"):
        FINGERPRINT["platform"] = "Lovable Cloud"

    if r.status_code != 200:
        return [], r.status_code
    try:
        spec = r.json()
    except Exception:
        return [], r.status_code

    if not FINGERPRINT.get("ref") and spec.get("host"):
        FINGERPRINT["ref"] = spec["host"].split(".")[0]

    names = set(spec.get("definitions", {}).keys())
    for p, ops in spec.get("paths", {}).items():
        if not p.startswith("/") or len(p) == 1 or "{" in p:
            continue
        t = p.strip("/")
        names.add(t)
        TABLE_VERBS[t] = [v for v in WRITE_VERBS if v in ops]

    for t, d in spec.get("definitions", {}).items():
        TABLE_COLS[t] = list(d.get("properties", {}).keys())

    names.discard("")
    return sorted(names), r.status_code


READ_VERDICT = {}   # 테이블 -> 읽기 프로빙 결과 (probe에서 채움)
PROBE_FINDINGS = [] # 통합 리포트용 위험 항목 수집


def report_write_grants():
    """읽기 판정과 교차해서 쓰기 GRANT 위험을 평가. 쓰기 요청은 안 보냄."""
    for t, verbs in sorted(TABLE_VERBS.items()):
        if not verbs:
            continue
        vlist = "/".join(v.upper() for v in verbs)
        read = READ_VERDICT.get(t, "")

        if read == "SAFE":
            note = ("읽기 정책은 있는데 쓰기 정책이 있는지는 밖에서 확인 불가. "
                    "누군가 몰래 데이터를 넣거나 지울 수 있을지 모름. 개발자에게 INSERT/UPDATE 정책 확인 요청.")
            print(f"    [? ] WARN     {t:20} 읽기는 막혔지만 anon {vlist} 권한이 열려 있음")
            print(f"         -> {note}")
        elif read == "CRITICAL":
            note = "읽기가 이미 열려 있어 우선순위는 읽기 차단이 먼저."
            print(f"    [? ] WARN     {t:20} anon {vlist} 권한 있음 (읽기도 이미 뚫림)")
            print(f"         -> {note}")
        else:
            note = "쓰기 정책 유무는 확인 불가. 개발자에게 INSERT/UPDATE 정책 확인 요청."
            print(f"    [? ] WARN     {t:20} anon {vlist} 권한 있음")
            print(f"         -> {note}")

        PROBE_FINDINGS.append({
            "severity": "WARN",
            "rule": f"라이브 프로빙: {t} 쓰기 권한(anon {vlist})",
            "file": "", "line": 0,
            "match": f"{t} → anon {vlist} GRANT",
            "note": note,
        })


def report_sensitive_cols():
    for t, cols in sorted(TABLE_COLS.items()):
        hit = [c for c in cols if any(s in c.lower() for s in SENSITIVE_COLS)]
        if hit:
            print(f"    [--] INFO     {t:20} 민감 컬럼 존재: {', '.join(hit)}")


def verdict(status, body):
    if status == 200:
        if isinstance(body, list) and len(body) > 0:
            return "CRITICAL", "anon이 실제 데이터를 읽음 = RLS 없음"
        if isinstance(body, list):
            return "WARN", "200이지만 빈 배열 — 판정 불가 (빈 테이블이거나, RLS가 행을 걸러냈거나, 읽기만 막고 쓰기는 열려 있을 수 있음)"
        return "WARN", "200이지만 형태 불명"

    # 401/403 은 원인이 두 갈래 — 응답 본문으로 구분
    if status in (401, 403):
        msg = ""
        code = ""
        if isinstance(body, dict):
            msg = (body.get("message") or "").lower()
            code = (body.get("code") or body.get("sb_error_code") or "")
        if "invalid api key" in msg or "no api key" in msg or "api key type" in msg:
            return "ERROR", "키가 무효 — 판정 불가 (RLS 여부와 무관)"
        # PostgREST 권한/정책 거부: code 42501, "permission denied", "policy"
        if code == "42501" or "permission denied" in msg or "policy" in msg or "row-level" in msg:
            return "SAFE", "정책이 차단 = RLS 작동 중"
        return "SAFE", f"{status} 차단됨 (원인 미상 — 응답 확인 필요)"

    if status == 404:
        return "INFO", "테이블 없음"
    return "WARN", f"예상 밖 응답 {status}"


def probe(base, key, known_tables=None):
    print(f"\n--- {base}")
    tables, sc = list_tables(base, key)

    used_fallback = False
    if not tables:
        if known_tables:
            print(f"    (테이블 목록 조회 막힘 — 2026-04 이후 정상 → 코드에서 뽑은 테이블명으로 직접 프로빙)")
            tables = known_tables
            used_fallback = True
            # 폴백 시엔 헤더 조합이 아직 확정 안 됨 → apikey+Bearer 기본
            if not WORKING_MODE.get("fn"):
                WORKING_MODE["fn"] = HEADER_MODES[0][1]
        else:
            print(f"    테이블 목록 실패 (status {sc}), 코드에서도 테이블명을 못 찾음")
            print(f"    → --table 로 테이블명을 직접 넘기면 계속 진행됨")
            return

    if FINGERPRINT:
        print(f"    지문: {', '.join(f'{k}={v}' for k, v in FINGERPRINT.items())}")
    print(f"    테이블 {len(tables)}개: {', '.join(tables)}\n")

    # 1단계: 읽기 프로빙 (GET) — 결과를 READ_VERDICT에 저장
    print("    [읽기 점검]")
    for t in tables:
        try:
            r = requests.get(f"{base}/rest/v1/{t}",
                             params={"select": "*", "limit": 1},
                             headers=headers_for(key), timeout=15)
        except Exception as e:
            print(f"    [ERR ] {t}: {e}")
            continue
        capture(f"table_{t}", r)
        try:
            body = r.json()
        except Exception:
            body = None
        sev, why = verdict(r.status_code, body)
        READ_VERDICT[t] = sev
        mark = {"CRITICAL": "[!!]", "WARN": "[? ]", "SAFE": "[ok]",
                "ERROR": "[xx]", "INFO": "[--]"}.get(sev, "[  ]")
        print(f"    {mark} {sev:8} {t:20} {r.status_code}  {why}")
        leaked = ""
        if sev == "CRITICAL":
            row = body[0]
            cols = ", ".join(list(row.keys())[:6])
            leaked = cols
            print(f"         유출된 컬럼: {cols}")
        # 통합 리포트용 수집 (SAFE/INFO는 정상이라 제외, 위험만)
        if sev in ("CRITICAL", "WARN", "ERROR"):
            PROBE_FINDINGS.append({
                "severity": sev if sev != "ERROR" else "INFO",
                "rule": f"라이브 프로빙: {t} 테이블 읽기",
                "file": base, "line": 0,
                "match": f"{t} → HTTP {r.status_code}",
                "note": why + (f" / 유출 컬럼: {leaked}" if leaked else ""),
            })

    # 2단계: 쓰기 GRANT 교차 판정 (introspection 성공 시에만 GRANT 정보 있음)
    if not used_fallback and TABLE_VERBS:
        print("\n    [쓰기 권한 점검]")
        report_write_grants()

    # 3단계: 민감 컬럼
    if not used_fallback and TABLE_COLS:
        print("\n    [민감 정보 점검]")
        report_sensitive_cols()
    print()


def parse_args(argv):
    """--url / --key / --table 를 직접 주면 폴더 스캔을 건너뜀."""
    url = key = None
    tables = []
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--url" and i + 1 < len(argv):
            url = argv[i + 1]; i += 2
        elif argv[i] == "--key" and i + 1 < len(argv):
            key = argv[i + 1]; i += 2
        elif argv[i] == "--table" and i + 1 < len(argv):
            tables.append(argv[i + 1]); i += 2
        else:
            rest.append(argv[i]); i += 1
    return url, key, tables, (rest[0] if rest else ".")


def run(target=".", url=None, key=None, tables=None):
    """라이브 프로빙 실행 → PROBE_FINDINGS 반환 (실행기에서 import용)."""
    global PROBE_FINDINGS, READ_VERDICT, TABLE_VERBS, TABLE_COLS, FINGERPRINT, WORKING_MODE
    PROBE_FINDINGS = []
    READ_VERDICT = {}
    TABLE_VERBS = {}
    TABLE_COLS = {}
    FINGERPRINT = {}
    WORKING_MODE = {}

    if url and key:
        cfg = {"urls": [url.rstrip("/")], "publishable": [key], "secret": [], "source": "직접 입력"}
    else:
        cfg = find_config(target)

    print("\n=== 설정값 추출 ===")
    print(f"  출처      : {cfg['source']}")
    print(f"  엔드포인트 : {cfg['urls']}")
    print(f"  공개 키    : {[k[:24] + '...' for k in cfg['publishable']]}")
    if cfg["secret"]:
        print(f"  !! 시크릿 키가 코드에 있음: {len(cfg['secret'])}건 — 즉시 폐기 대상")
        PROBE_FINDINGS.append({
            "severity": "CRITICAL", "rule": "코드에 Supabase 시크릿 키",
            "file": cfg.get("source", ""), "line": 0,
            "match": f"{len(cfg['secret'])}건", "note": "즉시 폐기 대상. 클라이언트에 secret 키가 있으면 DB 전체 우회 가능.",
        })

    if not cfg["publishable"]:
        print("\n공개 키를 못 찾음. 라이브 프로빙 건너뜀.")
        return PROBE_FINDINGS

    if not tables and os.path.isdir(target):
        tables = extract_tables(target)
        if tables:
            print(f"  코드에서 찾은 테이블: {', '.join(tables)}")

    kk = cfg["publishable"][0]
    for base in cfg["urls"]:
        try:
            probe(base.rstrip("/"), kk, known_tables=tables or None)
        except Exception as e:
            print(f"\n--- {base}\n    실패: {e}")

    # 읽기 GET만으로는 밖에서 판정할 수 없는 영역 — 과장하지 않고 명시
    if READ_VERDICT:
        PROBE_FINDINGS.append({
            "severity": "INFO", "rule": "라이브 점검 판정 불가 영역",
            "file": "", "line": 0, "match": "",
            "note": "읽기 요청만 보냈기 때문에 쓰기 정책(INSERT/UPDATE의 WITH CHECK), "
                    "rpc 함수(SECURITY DEFINER), 스토리지 버킷, 뷰(security_invoker)는 밖에서 판정할 수 없어요. "
                    "Supabase 대시보드의 Security Advisor로 꼭 확인하세요.",
        })

    if CAPTURE_ENABLED:
        print(f"\n응답 원본은 ./{CAPTURE_DIR}/ 에 저장됨 (사지방 복귀 후 오프라인 개발용)\n")
    return PROBE_FINDINGS


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--capture" in args:
        args.remove("--capture")
        CAPTURE_ENABLED = True
    ARG_URL, ARG_KEY, ARG_TABLES, TARGET = parse_args(args)
    if ARG_URL and "lovable.cloud" in ARG_URL:
        print("  (Lovable Cloud 감지 — 직결 엔드포인트도 넣으려면 PROJECT_ID를 --url 로 하나 더 주면 됨)")
    run(target=TARGET, url=ARG_URL, key=ARG_KEY, tables=ARG_TABLES)
