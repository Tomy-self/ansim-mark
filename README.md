# AI 앱 안심마크

**AI로 만든 앱이 언제, 무엇을, 누가 확인했는지 이용자에게 공개하는 2단계 점검 체계와 그 점검 엔진입니다.**

> 🏆 **제28회 이데일리 아이디어 유니버시아드 대상 (산업 부문, 2026)**
> 이 저장소는 수상작 「AI 앱 안심마크」의 1단계 자동 점검 엔진과 2단계 공개 확인서 발급 도구입니다. 아이디어만 낸 것이 아니라, 직접 만든 엔진으로 실제 앱을 점검한 결과를 근거로 제안했습니다.

| 직접 점검한 AI 생성 앱 | 문제 없음 | 확인 필요 | 지금 고쳐야 함 |
|---|---|---|---|
| 243개 | 76% | 16% | 6% |

---

## 문제: 보안 결과는 만든 사람만 본다

Lovable·Bolt·Cursor 같은 도구로 개발 경험 없이도 앱을 만들고 배포하는 사람이 빠르게 늘었습니다. 그런데 이런 앱은 같은 실수를 반복합니다. 비밀 키가 화면 코드에 그대로 들어 있거나, 데이터 잠금(RLS)이 꺼져 있어 로그인하지 않은 사람도 회원 데이터를 읽을 수 있습니다. 2025년 Lovable로 만든 앱에서 RLS 노출이 대량으로 발견된 사건(CVE-2025-48757)이 대표적입니다.

기존 해결책에는 두 가지 빈자리가 있습니다.

1. **만든 사람에게는 결과가 어렵습니다.** 보안 리포트는 "RLS 미설정", "IDOR" 같은 개발자 용어로 나옵니다. 앱을 만든 사람은 무엇을 어떻게 고쳐야 할지 모릅니다.
2. **쓰는 사람에게는 결과가 보이지 않습니다.** 플랫폼의 보안 스캔은 만든 사람에게만 비공개로 알려 줍니다. 그 앱에 개인정보를 넣는 이용자는 점검을 받았는지조차 알 수 없습니다.

## 해결: 자동 점검 → 사람 확인 → 공개 확인서

| 단계 | 하는 일 | 이 저장소 |
|---|---|---|
| **1단계 자동 점검** (무료) | 저장소나 사이트 주소를 넣으면 1분 안에 비밀 키 노출, 데이터 잠금, 서버 인증 누락, IDOR 의심을 찾습니다. 문제마다 **"이 문장을 AI 도구에 그대로 붙여 넣으세요"라는 수정 프롬프트**를 함께 줍니다. | `scanner.py`, `probe.py`, `report*.py`, `server.py` |
| **2단계 사람 확인** | 자동 점검이 밖에서 판정할 수 없는 영역(쓰기 정책, 실제 차단 여부)을 앱 주인의 서면 동의를 받은 뒤 검증관이 확인합니다. 검증관은 보안 분야 복무를 마친 전역자 중 앱 검증 실기 평가를 통과한 사람으로 구성하는 것을 목표로 합니다. | 절차 설계 |
| **공개 확인서** | 점검일, 점검한 판, 범위, 검수자, 유효 기간(90일), 철회 여부를 담은 공개 페이지를 발급합니다. 앱 주인은 사이트 아래쪽에 이 페이지로 가는 링크를 답니다. | `tools/mark.py` → [견본 확인서](https://tomy-self.github.io/ansim-mark/sample-cert.html) |

### 마크가 말하지 않는 것을 먼저 정했습니다

"안심"을 내세우는 표시는 과장되기 쉽습니다. 2008년 스캔 통과 표시를 단 사이트에서 취약점이 나온 Hacker Safe 사례와, 재점검 없이 표시를 유지해 2014년 제재를 받은 TRUSTe 사례가 그 결과입니다. 그래서 확인서는 **"그 날짜에, 그 범위를, 이렇게 확인했다"까지만** 말합니다.

- 확인서마다 "이 확인서가 말하지 않는 것"을 고정 문구로 넣습니다. 앱 전체가 안전하다는 뜻이 아니며, 점검일 뒤의 변경은 반영되지 않습니다.
- 유효 기간이 지나면 페이지가 스스로 만료를 표시하고, 중대한 문제가 확인되면 "거둬들임"으로 바뀝니다.
- 발급 도구는 기록에 "안전합니다", "인증", "공인", "보증" 같은 말이 들어가면 경고합니다.

## 1단계 엔진이 찾는 것

| 영역 | 찾는 것 | 등급 |
|---|---|---|
| 비밀 키 노출 | OpenAI·Anthropic·GitHub·Stripe·Slack 키, Supabase `sb_secret_`/`service_role` JWT, `.gitignore`에 빠진 `.env` | 🔴 |
| 데이터 잠금(RLS) | 마이그레이션 SQL에서 RLS를 켜지 않은 테이블, `USING (true)`처럼 누구에게나 열린 정책 | 🟡 |
| 서버 인증 누락 | DB에 쓰는 서버 함수(TanStack `createServerFn`, Next.js Route Handler, Express)에 로그인 확인이 없음 | 🔴/🟡 |
| IDOR 의심 | RLS를 우회하는 `service_role` 클라이언트로 조회하면서 "본인 것만" 조건이 없음 | 🟡 |
| 잘 된 점 | RLS 활성화, 정책 존재, 서버 인증, 소유자 필터, `.env` 제외 | 🟢 |
| 점검 범위 | 이번 점검이 **본 것과 못 본 것**을 따로 표시. 못 본 영역은 잘 된 점으로 세지 않음 | 🔎 |

리포트 견본: [sample-report.html](https://tomy-self.github.io/ansim-mark/sample-report.html) (가상의 앱을 실제 엔진으로 점검한 결과)

## 구조

```
 사용자 ─▶ 웹 페이지 ──POST /scan──▶ FastAPI (server.py)
                                       │  ① 입력 판별·SSRF 검사
                                       │  ② 저장소 zip / 사이트 JS 번들 수집
                                       ▼
                       scan_worker.py (별도 프로세스, 90초 제한)
                                       │
            ┌──────────────────────────┴───────────────────────┐
            ▼                                                   ▼
  scanner.py  정적 분석                           probe.py  라이브 점검 (CLI, 동의한 앱만)
  · 시크릿 정규식 + 가짜 키 필터                   · 코드에서 Supabase 설정·테이블명 추출
  · JWT role 분류                                  · 테이블별 읽기 GET 1행 → RLS 동작 판정
  · 서버 인증 누락 / IDOR 휴리스틱
  · 마이그레이션 RLS 정적 판정
            └──────────────────────────┬───────────────────────┘
                                       ▼
                 vibescan.run_all  중복 제거·심각도 정렬
                                       ▼
          report.py / report_html.py  비개발자용 리포트 + 수정 프롬프트 + 점검 범위
                                       ▼
          tools/mark.py  2단계 사람 확인 결과 → 공개 확인서
```

| 파일 | 역할 |
|---|---|
| `scanner.py` | 정적 분석: 시크릿, `.env`, 서버 인증·IDOR 휴리스틱, 마이그레이션 RLS 판정, 잘 된 점, 점검 범위 계산 |
| `probe.py` | 라이브 점검: 설정값 추출, 테이블명 추출, 읽기 프로빙, 응답 판정 |
| `vibescan.py` | CLI 진입점이자 `run_all()` (정적 → 라이브 → 중복 제거·정렬) |
| `report.py`, `report_html.py` | 규칙별 템플릿으로 리포트 생성. **LLM 호출 없이 결정론적**이라 같은 코드는 언제나 같은 결과 |
| `server.py`, `scan_worker.py` | 웹 API와 격리된 스캔 실행기 |
| `tools/mark.py` | 공개 확인서 발급, 기록 검증, 과장 표현 경고 |
| `tests/` | 보안·점검 범위·라이브 점검 안전장치 회귀 테스트 51개 |

## 설계에서 고민한 것

**1. 오탐 관리가 탐지만큼 중요하다**
- `sk-abcdefghijklmnop…` 같은 가짜 키는 엔트로피가 오히려 최대라서 엔트로피 기준으로는 걸러지지 않습니다. 연속·반복 문자와 더미 단어로 거르는 필터를 따로 둡니다.
- Supabase anon/publishable 키와 Firebase `apiKey`는 **설계상 공개되는 키**라 정보로만 표시합니다.
- 화면에서 로그인을 막는 코드(`beforeLoad` + `redirect`)는 UX일 뿐 서버 보안이 아닙니다. 대표적인 오탐 함정이라 따로 처리합니다.

**2. 판정할 수 없는 것은 판정할 수 없다고 말한다**
- 로그인 없이 보낸 요청에 `200 []`가 오면, 빈 테이블인지 RLS가 행을 걸러낸 것인지 밖에서는 알 수 없습니다. 그래서 "안전"이 아니라 **판정 불가**로 표시합니다.
- 읽기 요청만으로는 쓰기 정책(`WITH CHECK`), `SECURITY DEFINER` rpc, 스토리지 버킷을 볼 수 없습니다. 이 한계를 리포트에 고정 문구로 적고, 바로 이 영역을 2단계 사람 확인이 맡습니다.

**3. 외부 변화에 맞춰 엔진을 고친다**
- 2026-04-08부터 Supabase는 공개 키로 테이블 목록(OpenAPI)을 볼 수 없게 막았습니다. 그래서 테이블명을 코드의 `supabase.from('…')` 호출과 마이그레이션의 `create table`에서 직접 추출하도록 바꿨습니다.

**4. 법적 경계를 아키텍처로 지킨다**
- 대법원 2021도5555는 접근 권한을 "서비스 제공자가 부여한 권한" 기준으로 판단합니다. 웹에서는 신청자가 앱의 주인인지 확인할 수 없습니다.
- 그래서 **웹 진단은 앱의 DB에 어떤 요청도 보내지 않고** 코드와 설정만 분석합니다. 실제 DB 점검은 본인 앱이나 서면 동의를 받은 앱에만, CLI에서 `--probe`를 줄 때만, 읽기 GET 1행으로 하며 받은 데이터 값은 저장하지 않습니다.

## 웹 서비스 보안

남이 준 URL을 서버가 가져오는 서비스는 그 자체가 SSRF 표적이 됩니다. OWASP SSRF Prevention Cheat Sheet를 기준으로 막았습니다.

| 위협 | 대응 | 코드 |
|---|---|---|
| 내부망 접근 (SSRF) | http/https, 80/443만 허용. 해석된 **모든** IP가 공개 주소여야 통과. IPv4-mapped 주소도 풀어서 검사 | `resolve_public()` |
| DNS rebinding | 검증한 IP로 TCP 연결을 고정하고 Host·SNI·인증서 검증은 원래 호스트명 유지 | `_PinnedAdapter` |
| 리다이렉트 우회 | 자동 리다이렉트를 끄고 단계마다 재검증 (최대 5회) | `safe_get()` |
| Zip slip · 압축 폭탄 | 폴더 밖 경로·심볼릭 링크 건너뜀. 실제 풀린 바이트를 세고 항목 수 상한 | `safe_extract()` |
| 속도 제한 우회 | 클라이언트가 넣은 X-Forwarded-For는 무시하고 프록시가 붙인 값만 신뢰 | `client_ip()` |
| 자원 고갈 | IP당 시간당 5회, 스캔 직렬 처리, 별도 프로세스 90초 제한, 다운로드 크기 상한 | `create_scan()`, `run_job()` |
| 데이터 잔존 | 받은 코드는 스캔 직후 삭제, 결과는 메모리에 1시간만 보관, 응답 원본 저장 끔 | `run_job()` |

## 실행 방법

```bash
pip install -r requirements.txt

# CLI: 기본은 정적 분석만
python vibescan.py ~/my-app --html        # report_my-app.html 생성
python vibescan.py ~/my-app --probe       # 정적 + 라이브 (본인 앱이거나 서면 동의를 받은 앱만)

# 웹 API
uvicorn server:app --port 8000

# 공개 확인서
python tools/mark.py sample               # docs/ 견본 다시 만들기
python tools/mark.py cert 기록.json        # 확인서 발급

# 테스트 (51개, 네트워크 없이 실행)
python -m unittest discover -s tests
```

## 한계와 다음 단계

- 정규식·파일 단위 휴리스틱이라 다른 파일의 미들웨어로 인증하는 경우 등은 놓치거나 오탐할 수 있습니다. → AST·taint 분석(Semgrep/CodeQL)으로 옮길 예정
- 정밀도·재현율을 라벨링된 정답셋으로 아직 측정하지 않았습니다. → 규칙별 혼동 행렬 측정 예정
- 웹에서 라이브 점검을 하려면 소유권 확인(DNS TXT 또는 파일 인증)이 필요합니다.
- 2단계 검증관의 실기 평가 기준과 건당 검증 시간은 파일럿으로 측정할 계획입니다.

## 만든 사람

**윤세진** · 홍익대학교 컴퓨터공학과 · 보안 분야 복무 후 전역

기획, 점검 규칙 설계, 개발, 실측을 혼자 했습니다. 개발에는 AI 코딩 도구를 적극적으로 썼고, 점검 규칙과 판정 기준, 보안 설계, 테스트 검증은 직접 정하고 확인했습니다. AI로 앱을 만드는 사람이 늘수록 그 앱을 쓰는 사람도 판단할 근거가 있어야 한다고 생각해 이 프로젝트를 시작했습니다.

## 참고 자료

- [CVE-2025-48757 — Lovable 앱 RLS 노출 (Matt Palmer)](https://mattpalmer.io/posts/statement-on-CVE-2025-48757/)
- [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security) · [OpenAPI 접근 차단 공지](https://supabase.com/changelog/42949-breaking-change-removing-access-to-openapi-spec-via-the-anon-key)
- [OWASP Top 10:2025 A01 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Lovable Security View 문서](https://docs.lovable.dev/features/security-view)
