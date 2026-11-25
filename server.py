#!/usr/bin/env python3
"""
server.py — 웹에서 바로 스캔하는 API (Render 무료 플랜용)
  uvicorn server:app --port 8000

  POST /scan        {"target": "<GitHub 레포 주소 또는 사이트 주소>", "agreed": true} -> {"id"}
  GET  /scan/{id}   -> {"status": queued|running|done|error, "html", "counts", "coverage", "kind", "error", "ahead"}
                       coverage = 이번 점검이 본 영역과 못 본 영역 (scanner.coverage)

흐름: 입력 판별 → 임시폴더로 받기(레포 zip / 사이트 JS 번들) → scan_worker.py 별도 프로세스
     → 리포트 HTML을 메모리에 1시간 보관 → 임시폴더 즉시 삭제. 코드·결과는 디스크에 남지 않음.
"""
import io, ipaddress, json, os, queue, re, shutil, socket, subprocess, sys
import tempfile, threading, time, uuid, zipfile
from collections import defaultdict, deque
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

HERE = os.path.dirname(os.path.abspath(__file__))

ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:8080,http://127.0.0.1:8080",
).split(",")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")   # 없으면 GitHub API 시간당 60회 제한

MAX_REPO_BYTES = 50 * 1024 * 1024
MAX_JS_FILES = 20
MAX_JS_BYTES = 5 * 1024 * 1024
MAX_ZIP_ENTRIES = 20000
MAX_UNZIP_BYTES = 300 * 1024 * 1024
SCAN_TIMEOUT = 90
RESULT_TTL = 3600
RATE_LIMIT = 5          # IP당 시간당 스캔 수
UA = {"User-Agent": "ansim-mark-scanner/1.0"}

GITHUB_RE = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?(?:[#?].*)?$")


class ScanError(Exception):
    """사용자에게 그대로 보여줄 메시지."""


# ---------------------------------------------------------------
# SSRF 방어: 공개 인터넷 주소만, 그리고 "검증한 그 IP"로만 연결
#   resolve → 검증 → requests가 다시 resolve 하면 그 사이 DNS 응답이 바뀔 수 있음(TOCTOU, DNS rebinding).
#   그래서 검증한 IP로 TCP 연결을 고정하고, Host 헤더·SNI·인증서 검증은 원래 호스트명을 그대로 씀.
#   https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
# ---------------------------------------------------------------
ALLOWED_PORTS = {80, 443}


def _is_public_ip(ip):
    ip = ipaddress.ip_address(ip)
    if getattr(ip, "ipv4_mapped", None):     # ::ffff:127.0.0.1 같은 IPv4-mapped 주소는 풀어서 검사
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_public(url):
    """URL을 검사하고, 연결에 쓸 검증된 IP 하나를 돌려준다."""
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ScanError("http:// 또는 https:// 로 시작하는 주소를 넣어주세요.")
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        raise ScanError("주소 형식이 올바르지 않아요.")
    if port not in ALLOWED_PORTS:
        raise ScanError("80/443 포트의 주소만 점검할 수 있어요.")
    try:
        infos = socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ScanError("주소를 찾을 수 없어요. 철자를 확인해 주세요.")
    ips = [info[4][0] for info in infos]
    # 하나라도 내부 주소면 거부 (공개/내부를 섞어 돌려주는 DNS 대비)
    if not ips or not all(_is_public_ip(ip) for ip in ips):
        raise ScanError("내부망 주소는 점검할 수 없어요.")
    return ips[0]


class _PinnedAdapter(HTTPAdapter):
    """모든 연결을 미리 검증한 IP로 보내는 어댑터. 호스트명은 Host/SNI/인증서 검증에만 쓰임."""

    def __init__(self, ip):
        self._ip = ip
        super().__init__(max_retries=0)

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        ip = self._ip

        # urllib3 2.x에서 host(=Host 헤더·SNI·인증서 검증)는 _dns_host에서 읽히므로 그건 건드리지 않고,
        # TCP 소켓을 여는 _new_conn만 고정 IP로 바꾼다.
        def _new_conn(c):
            try:
                return urllib3.util.connection.create_connection(
                    (ip, c.port), c.timeout,
                    source_address=c.source_address, socket_options=c.socket_options)
            except socket.timeout as e:
                raise urllib3.exceptions.ConnectTimeoutError(c, f"Connection to {c.host} timed out.") from e
            except OSError as e:
                raise urllib3.exceptions.NewConnectionError(c, f"Failed to establish a new connection: {e}") from e

        _HTTP = type("PinnedHTTPConnection", (urllib3.connection.HTTPConnection,), {"_new_conn": _new_conn})
        _HTTPS = type("PinnedHTTPSConnection", (urllib3.connection.HTTPSConnection,), {"_new_conn": _new_conn})
        self.poolmanager.pool_classes_by_scheme = {
            "http": type("PinnedHTTPPool", (urllib3.HTTPConnectionPool,), {"ConnectionCls": _HTTP}),
            "https": type("PinnedHTTPSPool", (urllib3.HTTPSConnectionPool,), {"ConnectionCls": _HTTPS}),
        }


def pinned_get(url, **kw):
    ip = resolve_public(url)
    with requests.Session() as sess:
        sess.trust_env = False                  # 환경변수 프록시로 새는 것 방지
        sess.mount("http://", _PinnedAdapter(ip))
        sess.mount("https://", _PinnedAdapter(ip))
        return sess.get(url, headers=UA, timeout=15, allow_redirects=False, **kw)


def safe_get(url, max_bytes):
    """리다이렉트를 한 단계씩 따라가며 매번 검증·IP 고정. 크기 상한 초과 시 중단."""
    for _ in range(5):
        r = pinned_get(url, stream=True)
        if r.is_redirect:
            url = urljoin(url, r.headers.get("Location", ""))
            r.close()
            continue
        buf = io.BytesIO()
        size = 0
        for chunk in r.iter_content(64 * 1024):
            size += len(chunk)
            if size > max_bytes:
                r.close()
                raise ScanError(f"파일이 너무 커요 ({max_bytes // 1024 // 1024}MB 초과).")
            buf.write(chunk)
        return r, url, buf
    raise ScanError("리다이렉트가 너무 많아요.")


def safe_extract(z, dest):
    """zip slip(폴더 밖 경로)·압축 폭탄 방어. 헤더 크기는 거짓일 수 있어 실제 풀린 바이트를 센다."""
    root = os.path.realpath(dest)
    infos = z.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ScanError("저장소 파일 수가 너무 많아요.")
    total = 0
    for m in infos:
        p = os.path.realpath(os.path.join(dest, m.filename))
        if not p.startswith(root + os.sep):
            continue
        if m.is_dir():
            os.makedirs(p, exist_ok=True)
            continue
        # 심볼릭 링크 항목은 건너뜀 (unix 모드 상위 비트)
        if (m.external_attr >> 16) & 0o170000 == 0o120000:
            continue
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with z.open(m) as src, open(p, "wb") as out:
            while True:
                chunk = src.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UNZIP_BYTES:
                    raise ScanError("압축을 푼 크기가 너무 커요.")
                out.write(chunk)


# ---------------------------------------------------------------
# 입력별로 임시폴더에 받기
# ---------------------------------------------------------------
def fetch_repo(owner, repo, dest):
    headers = dict(UA)
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    meta = requests.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers, timeout=15)
    if meta.status_code == 404:
        raise ScanError("저장소를 찾을 수 없어요. 공개(public) 저장소인지 확인해 주세요.")
    if meta.status_code == 403:
        raise ScanError("GitHub 요청 한도에 걸렸어요. 잠시 후 다시 시도해 주세요.")
    meta.raise_for_status()
    if meta.json().get("size", 0) * 1024 > MAX_REPO_BYTES * 4:
        raise ScanError("저장소가 너무 커요. 앱 코드만 있는 저장소로 시도해 주세요.")

    r, _, buf = safe_get(f"https://codeload.github.com/{owner}/{repo}/zip/HEAD", MAX_REPO_BYTES)
    if r.status_code != 200:
        raise ScanError("저장소를 내려받지 못했어요.")
    try:
        with zipfile.ZipFile(buf) as z:
            safe_extract(z, dest)
    except zipfile.BadZipFile:
        raise ScanError("저장소를 내려받지 못했어요.")
    return repo


SCRIPT_SRC_RE = re.compile(r"""<(?:script|link)\b[^>]*?(?:src|href)\s*=\s*["']([^"']+\.m?js(?:\?[^"']*)?)["']""", re.I)
# 번들 안에서 다른 청크를 부르는 경로 (Vite/Next: "/assets/index-abc.js", "./chunk-x.js")
CHUNK_RE = re.compile(r"""["'`]((?:/|\./)[\w./-]+\.m?js)["'`]""")
# HTML 안에 바로 쓴 스크립트. src가 있는 태그는 파일로 따로 받으므로 제외
INLINE_SCRIPT_RE = re.compile(r"""<script\b(?![^>]*\bsrc\s*=)([^>]*)>(.*?)</script\s*>""", re.I | re.S)
DATA_SCRIPT_RE = re.compile(r"""\btype\s*=\s*["']?[^"'\s>]*(?:json|template|text/html)""", re.I)


def has_inline_script(page):
    """실행되는 코드가 HTML 안에 있는가. JSON 데이터 블록과 빈 태그는 코드로 치지 않는다."""
    return any(body.strip() and not DATA_SCRIPT_RE.search(attrs)
               for attrs, body in INLINE_SCRIPT_RE.findall(page))


def fetch_site(url, dest):
    r, final_url, buf = safe_get(url, MAX_JS_BYTES)
    if r.status_code in (401, 403):
        raise ScanError("로그인해야 볼 수 있는 주소예요. 미리보기 주소 말고 공개(Publish)된 주소나 GitHub 주소로 시도해 주세요.")
    if r.status_code == 404:
        raise ScanError("페이지를 찾을 수 없어요. 주소를 다시 확인해 주세요.")
    if r.status_code >= 400:
        raise ScanError(f"사이트가 응답하지 않아요 (HTTP {r.status_code}). 잠시 후 다시 시도하거나 GitHub 주소로 시도해 주세요.")
    page = buf.getvalue().decode("utf-8", "ignore")
    host = urlparse(final_url).hostname
    with open(os.path.join(dest, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page)

    # probe.find_config 가 'assets' 폴더를 빌드 번들로 인식함
    adir = os.path.join(dest, "assets")
    os.makedirs(adir, exist_ok=True)
    todo = [urljoin(final_url, s) for s in SCRIPT_SRC_RE.findall(page)]
    seen = set()
    while todo and len(seen) < MAX_JS_FILES:
        js = todo.pop(0)
        if js in seen or urlparse(js).hostname != host:   # 같은 사이트 파일만
            continue
        seen.add(js)
        try:
            jr, _, jbuf = safe_get(js, MAX_JS_BYTES)
        except (ScanError, requests.RequestException):
            continue
        if jr.status_code != 200:
            continue
        text = jbuf.getvalue().decode("utf-8", "ignore")
        name = re.sub(r"[^\w.-]", "_", urlparse(js).path.strip("/"))[-120:] or "bundle.js"
        with open(os.path.join(adir, name), "w", encoding="utf-8") as fh:
            fh.write(text)
        todo += [urljoin(js, c) for c in CHUNK_RE.findall(text)]

    # index.html은 위에서 저장했으므로 HTML 안의 스크립트도 스캐너가 함께 읽는다
    if not seen and not has_inline_script(page):
        raise ScanError("이 페이지에서 점검할 코드를 찾지 못했어요. GitHub 주소로 시도해 보세요.")
    return host


def prepare(target, dest):
    target = target.strip()
    m = GITHUB_RE.match(target)
    if m:
        return fetch_repo(m.group(1), m.group(2), dest), "repo"
    if "github.com" in target:
        raise ScanError("GitHub 저장소 주소 형식이 아니에요. 예: https://github.com/아이디/앱이름")
    if not re.match(r"^https?://", target):
        target = "https://" + target
    return fetch_site(target, dest), "site"


# ---------------------------------------------------------------
# 작업 큐 (무료 플랜 메모리 512MB → 한 번에 하나씩)
# ---------------------------------------------------------------
JOBS = {}
JOB_ORDER = deque()
Q = queue.Queue()


def log_scan(job, seconds):
    """점검 1건의 집계용 한 줄. 몇 건을 어떤 결과로 점검했는지만 남긴다.
    주소·IP·코드 내용·발견 항목의 본문은 넣지 않는다 (약관 3번)."""
    line = {"status": job.get("status"), "kind": job.get("kind"),
            "counts": job.get("counts"), "sec": round(seconds, 1)}
    if job.get("status") == "error":
        line["err"] = (job.get("error") or "")[:30]
    print("SCANLOG " + json.dumps(line, ensure_ascii=False), file=sys.stderr, flush=True)


def run_job(job_id):
    job = JOBS[job_id]
    job["status"] = "running"
    started = time.time()
    job["kind"] = "repo" if "github.com" in job["target"] else "site"
    work = tempfile.mkdtemp(prefix="vibescan_")
    try:
        src = os.path.join(work, "src")
        os.makedirs(src)
        name, kind = prepare(job["target"], src)
        out = os.path.join(work, "result.json")
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(HERE, "scan_worker.py"), src, out, name, kind],
                cwd=work, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise ScanError("점검 시간이 너무 오래 걸려 중단했어요. 저장소가 크면 실패할 수 있어요.")
        if proc.returncode != 0 or not os.path.exists(out):
            print(proc.stderr[-2000:], file=sys.stderr)
            raise ScanError("점검 중 오류가 났어요. 잠시 후 다시 시도해 주세요.")
        with open(out, encoding="utf-8") as fh:
            job.update(json.load(fh))
        job["status"] = "done"
    except ScanError as e:
        job.update(status="error", error=str(e))
    except Exception as e:
        print(f"[job {job_id}] {e!r}", file=sys.stderr)
        job.update(status="error", error="점검 중 오류가 났어요. 잠시 후 다시 시도해 주세요.")
    finally:
        shutil.rmtree(work, ignore_errors=True)
        job["finished"] = time.time()
        log_scan(job, job["finished"] - started)


def worker():
    while True:
        job_id = Q.get()
        try:
            run_job(job_id)
        finally:
            Q.task_done()


def sweep():
    now = time.time()
    while JOB_ORDER and now - JOBS[JOB_ORDER[0]]["created"] > RESULT_TTL:
        JOBS.pop(JOB_ORDER.popleft(), None)


threading.Thread(target=worker, daemon=True).start()

# ---------------------------------------------------------------
# API
# ---------------------------------------------------------------
app = FastAPI(title="Vibe Scanner API")
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

HITS = defaultdict(deque)


# X-Forwarded-For 맨 앞 값은 클라이언트가 마음대로 넣을 수 있음 → 속도 제한 우회 가능.
# 프록시는 받은 값 뒤에 자기가 본 IP를 덧붙이므로, 오른쪽에서 TRUSTED_PROXY_HOPS번째 값이
# 우리 쪽 프록시가 직접 본 클라이언트 IP다. (Render: 3단 — 2026-10-11 실측)
TRUSTED_PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "3"))


def client_ip(request):
    fwd = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    if TRUSTED_PROXY_HOPS and len(fwd) >= TRUSTED_PROXY_HOPS:
        return fwd[-TRUSTED_PROXY_HOPS]
    return request.client.host


class ScanIn(BaseModel):
    target: str
    agreed: bool = False


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/scan")
def create_scan(body: ScanIn, request: Request):
    if not body.agreed:
        raise HTTPException(400, "이용약관에 동의해 주세요.")
    if not body.target.strip() or len(body.target) > 300:
        raise HTTPException(400, "주소를 확인해 주세요.")

    ip = client_ip(request)
    now = time.time()
    hits = HITS[ip]
    while hits and now - hits[0] > 3600:
        hits.popleft()
    if len(hits) >= RATE_LIMIT:
        raise HTTPException(429, "한 시간에 5번까지 점검할 수 있어요. 잠시 후 다시 시도해 주세요.")
    hits.append(now)

    sweep()
    job_id = uuid.uuid4().hex
    JOBS[job_id] = {"status": "queued", "target": body.target, "created": now}
    JOB_ORDER.append(job_id)
    Q.put(job_id)
    return {"id": job_id}


@app.get("/scan/{job_id}")
def get_scan(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "결과가 없거나 만료됐어요 (결과는 1시간만 보관해요).")
    out = {k: job.get(k) for k in ("status", "html", "counts", "error", "coverage", "kind")}
    if job["status"] == "queued":
        out["ahead"] = sum(1 for j in JOB_ORDER
                           if JOBS.get(j, {}).get("status") in ("queued", "running")
                           and JOBS[j]["created"] < job["created"])
    return out
