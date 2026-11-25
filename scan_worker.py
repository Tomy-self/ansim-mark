#!/usr/bin/env python3
"""
scan_worker.py — server.py가 스캔 1건마다 별도 프로세스로 띄우는 실행기.
  python scan_worker.py <받아온 폴더> <결과 json 경로> <리포트 이름>

별도 프로세스인 이유:
  - scanner/probe가 모듈 전역 상태(findings, PROBE_FINDINGS ...)를 씀 → 스캔끼리 섞이지 않게
  - 타임아웃 시 프로세스째 죽일 수 있음
"""
import contextlib, io, json, os, sys

import probe
import report
import report_html
import scanner
import vibescan


def main():
    root, out_path, name = sys.argv[1], sys.argv[2], sys.argv[3]
    # "site" = 배포 주소에서 받은 화면 코드, "repo" = 저장소. 화면 코드에는 서버 기준 검사를 돌리지 않는다
    kind = sys.argv[4] if len(sys.argv) > 4 else "repo"
    # GitHub zip은 "레포-HEAD/" 폴더 하나로 풀림 → 그 안을 루트로
    entries = os.listdir(root)
    if len(entries) == 1 and os.path.isdir(os.path.join(root, entries[0])):
        root = os.path.join(root, entries[0])
    probe.CAPTURE_ENABLED = False   # 남의 앱 응답 원본을 디스크에 남기지 않음

    # 웹에서는 신청자가 대상 앱의 주인인지 확인할 방법이 없음 → DB에 요청을 보내는 라이브 점검은 하지 않음
    #   (대법원 2021도5555: 접근권한은 '서비스제공자가 부여한 권한' 기준. 본인 앱은 CLI로 라이브 점검)
    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        findings = vibescan.run_all(root, no_live=True, kind=kind)
    # 데이터베이스에 요청을 보내지 않았다는 사실은 '잘 된 점'이 아니다 → 항목으로 넣지 않고
    # 점검 범위 표에 '확인 못 함'으로 적는다
    cov = scanner.coverage(findings, scanner.FACTS, live=False)

    # 리포트에 서버 임시폴더 경로가 보이지 않게 상대경로로
    prefix = root.rstrip("/") + "/"
    for f in findings:
        for k in ("file", "_seen_at"):
            if isinstance(f.get(k), str):
                f[k] = f[k].replace(prefix, "")

    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("CRITICAL", "WARN", "INFO")}
    # GOOD: 실제로 확인한 긍정 신호 수 / UNKNOWN: 이번 점검으로 볼 수 없었던 영역 수
    counts["GOOD"] = sum(1 for f in findings
                         if f["severity"] == "INFO" and report.info_kind(f) == "good")
    counts["UNKNOWN"] = sum(1 for r in cov if r["status"] == "unknown")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"counts": counts, "kind": kind, "coverage": cov,
                   "html": report_html.build_html(findings, name, coverage=cov, kind=kind)},
                  fh, ensure_ascii=False)


if __name__ == "__main__":
    main()
