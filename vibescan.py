#!/usr/bin/env python3
"""
Vibe Coding Scanner — 통합 실행기
  python vibescan.py <폴더>            # 정적 분석만 (네트워크 요청 없음)
  python vibescan.py <폴더> --probe    # 정적 + (폴더의 .env로) 라이브
  python vibescan.py <폴더> --probe --url ... --key ...   # 라이브 대상 직접 지정
  python vibescan.py --probe --url ... --key ... --table todos   # 폴더 없이 라이브만

scanner.py(정적)와 probe.py(라이브)를 순서대로 부르고 결과를 심각도순으로 한 번에 출력.
라이브 요청은 --probe를 줄 때만 보낸다. 남의 앱은 서면 동의를 받은 뒤에만 쓴다.
"""
import os, sys

import scanner
import probe
import report as report_mod
import report_html as report_html_mod


def parse(argv):
    url = key = None
    tables, rest = [], []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--url" and i + 1 < len(argv):
            url = argv[i + 1]; i += 2
        elif a == "--key" and i + 1 < len(argv):
            key = argv[i + 1]; i += 2
        elif a == "--table" and i + 1 < len(argv):
            tables.append(argv[i + 1]); i += 2
        elif a == "--no-live":
            rest.append(a); i += 1
        elif a == "--report":
            rest.append(a); i += 1
        elif a == "--html":
            rest.append(a); i += 1
        else:
            rest.append(a); i += 1
    target = next((r for r in rest if not r.startswith("--")), ".")
    # --probe가 없으면 .env나 --url이 있어도 라이브 요청을 보내지 않는다
    no_live = "--no-live" in rest or "--probe" not in rest
    return url, key, tables, target, no_live, ("--report" in rest), ("--html" in rest)


ICON = {"CRITICAL": "[!!]", "WARN": "[? ]", "INFO": "[ok]"}
ORDER = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
COV_MARK = {"ok": "[확인]", "issue": "[주의]", "unknown": "[모름]", "na": "[없음]"}


def dedupe_sort(all_findings):
    """같은 rule이 여러 엔드포인트(프록시/직결)로 중복될 수 있음 → 하나로 합치고 심각도순 정렬."""
    seen = {}
    deduped = []
    for f in all_findings:
        k = (f["severity"], f["rule"])
        if k in seen:
            # 이미 있으면 엔드포인트 정보만 병합
            prev = seen[k]
            if f.get("file") and f["file"] not in prev.get("_seen_at", ""):
                prev["_seen_at"] = prev.get("_seen_at", "") + " " + f["file"]
            continue
        f = dict(f)
        f["_seen_at"] = f.get("file", "")
        seen[k] = f
        deduped.append(f)
    deduped.sort(key=lambda f: (ORDER.get(f["severity"], 9),
                                str(f.get("file", "")), f.get("line", 0)))
    return deduped


def run_all(target, url=None, key=None, tables=None, no_live=True, kind="repo"):
    """정적 → 라이브 → 중복제거·정렬. CLI(main)와 server.py가 같이 씀.
    라이브는 호출자가 no_live=False로 명시할 때만 돈다."""
    all_findings = []

    # 1) 정적 분석 (폴더가 있을 때만)
    have_folder = os.path.isdir(target)
    if have_folder:
        print(f"\n{'='*54}\n[1/2] 정적 분석 — {os.path.abspath(target)}\n{'='*54}")
        static = scanner.run(target, kind=kind)
        scanner._print_report(static, target)
        all_findings += static
    else:
        print(f"\n(폴더 '{target}' 없음 → 정적 분석 건너뜀, 라이브만)")

    # 2) 라이브 프로빙
    if not no_live:
        print(f"\n{'='*54}\n[2/2] 라이브 프로빙\n{'='*54}")
        # 폴더가 있으면 그 .env에서 자동 추출, 아니면 인자로 받은 url/key
        live = probe.run(target=target if have_folder else ".",
                         url=url, key=key, tables=tables)
        all_findings += live
    else:
        print("\n(라이브 점검 건너뜀: 본인 앱이거나 서면 동의를 받은 앱만 --probe로 실행)")

    return dedupe_sort(all_findings)


def main():
    url, key, tables, target, no_live, want_report, want_html = parse(sys.argv[1:])
    all_findings = run_all(target, url, key, tables, no_live)

    # 3) 통합 요약
    print(f"\n{'='*54}\n통합 결과 (심각도순)\n{'='*54}\n")

    if not all_findings:
        print("발견된 위험 항목 없음.\n")
    for f in all_findings:
        loc = f"{f['file']}:{f['line']}" if f.get("line") else f.get("file", "")
        print(f"{ICON.get(f['severity'],'[  ]')} {f['severity']:8} {f['rule']}")
        if loc:
            print(f"     {loc}")
        if f.get("match"):
            print(f"     {f['match']}")
        if f.get("note"):
            print(f"     -> {f['note']}")
        print()

    c = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    w = sum(1 for f in all_findings if f["severity"] == "WARN")
    i = sum(1 for f in all_findings if f["severity"] == "INFO")
    print(f"{'='*54}")
    print(f"  최종: 치명적 {c} / 확인필요 {w} / 정상·참고 {i}")
    print(f"{'='*54}\n")

    # 3-b) 점검 범위: 이번에 본 것과 못 본 것 (폴더를 점검했을 때만)
    #      live는 --probe를 줬고 실제로 읽기 요청이 나갔을 때만 True
    cov = None
    if os.path.isdir(target):
        cov = scanner.coverage(all_findings, scanner.FACTS,
                               live=(not no_live) and bool(probe.READ_VERDICT))
        print("점검 범위 (본 것과 못 본 것)")
        for r in cov:
            print(f"  {COV_MARK[r['status']]} {r['label']}")
            print(f"         {r['detail']}")
        print()

    # 4) 비개발자용 리포트 파일
    name = os.path.basename(os.path.abspath(target)) if os.path.isdir(target) else "scan"
    if want_report:
        md = report_mod.build_report(all_findings, name, coverage=cov)
        with open(f"report_{name}.md", "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"📄 마크다운 리포트: report_{name}.md")
    if want_html:
        h = report_html_mod.build_html(all_findings, name, coverage=cov)
        with open(f"report_{name}.html", "w", encoding="utf-8") as fh:
            fh.write(h)
        print(f"🌐 HTML 리포트: report_{name}.html  (더블클릭하면 브라우저에서 열려요)")
    if want_report or want_html:
        print()


if __name__ == "__main__":
    main()
