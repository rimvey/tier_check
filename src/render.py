#!/usr/bin/env python3
"""TSV → out/report.json, report.html, assets.json, assets.html (SPEC 1-1~1-3, 1-8, 4절)."""
import argparse, csv, datetime, html, json, os, socket
CATS = ["계정 관리", "서비스 관리", "파일 시스템"]
HERE = os.path.dirname(os.path.abspath(__file__))
esc = html.escape

def grade_of(total):  # 1-3
    return "상" if total >= 7 else "중" if total >= 5 else "하"

def os_name():
    try:
        for l in open("/etc/os-release"):
            if l.startswith("PRETTY_NAME="): return l.split("=", 1)[1].strip().strip('"')
    except OSError: pass
    return "Linux"

CSS = """body{font-family:system-ui,'Noto Sans KR',sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#1b1f23}
table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;vertical-align:top;font-size:.9rem}
th{background:#f6f8fa}.양호{color:#1a7f37;font-weight:600}.취약{color:#cf222e;font-weight:600}.확인-불가{color:#9a6700;font-weight:600}.해당-없음{color:#656d76;font-weight:600}
.ev{font-family:ui-monospace,monospace;font-size:.8rem;word-break:break-all}nav a{margin-right:1rem}"""

def page(title, body):
    return f"<!doctype html><html lang=ko><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{esc(title)}</title><style>{CSS}</style><nav><a href=report.html>점검 결과서</a><a href=assets.html>자산 관리 대장</a></nav>{body}</html>"

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--tsv"); ap.add_argument("--out"); ap.add_argument("--root", default="/")
    a = ap.parse_args(); host = socket.gethostname(); now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    # ---- 자산 ----
    assets = []
    for x in json.load(open(os.path.join(HERE, "assets_input.json"))):
        x = dict(x); x["name"] = host if x["name"] == "auto" else x["name"]; x["os"] = os_name() if x["os"] == "auto" else x["os"]
        x["importance"] = grade_of(x["c"] + x["i"] + x["a"]); assets.append(x)
    json.dump(assets, open(os.path.join(a.out, "assets.json"), "w"), ensure_ascii=False, indent=2)
    rows = "".join(f"<tr><td>{i+1}</td><td>{esc(x['type'])}</td><td>{esc(x['name'])}</td><td>{esc(x['purpose'])}</td><td>{esc(x['zone'])}</td><td>{esc(x['os'])}</td><td>{esc(x['mode'])}</td><td>{esc(x['owner'])}</td><td>C{x['c']}·I{x['i']}·A{x['a']} = {x['c']+x['i']+x['a']} → <b>{x['importance']}</b></td></tr>" for i, x in enumerate(assets))
    open(os.path.join(a.out, "assets.html"), "w").write(page("자산 관리 대장", f"""<h1>자산 관리 대장</h1><p>진단 7단계 중 1~2단계(자산 식별·중요도 산정). 중요도 = C+I+A 합산(7~9 상, 5~6 중, 3~4 하).</p>
<table><tr><th>No</th><th>자산 유형</th><th>자산명(호스트명)</th><th>용도</th><th>망 위치</th><th>운영체제·모델</th><th>운영 형태</th><th>담당자</th><th>중요도</th></tr>{rows}</table>"""))
    # ---- 점검 결과 ----
    items = []
    for r in csv.reader(open(a.tsv, encoding="utf-8"), delimiter="\t", quoting=csv.QUOTE_NONE):
        if len(r) < 6: continue
        items.append(dict(id=r[0], category=r[1], name=r[2], grade=r[3], result=r[4], evidence=r[5]))
    summary = {}
    for c in CATS:
        its = [i for i in items if i["category"] == c]; cnt = lambda s: sum(i["result"] == s for i in its)
        total = cnt("양호") + cnt("취약") + cnt("확인 불가")          # 1-8: 해당 없음 제외
        summary[c] = dict(total=total, vuln=cnt("취약"), ok=cnt("양호"), unknown=cnt("확인 불가"), na=cnt("해당 없음"), rate=(cnt("취약") / total if total else 0.0))
    tot = sum(s["total"] for s in summary.values()); vul = sum(s["vuln"] for s in summary.values())
    totals = dict(total=tot, vuln=vul, unknown=sum(s["unknown"] for s in summary.values()), rate=(vul / tot if tot else 0.0))
    json.dump(dict(host=host, generated=now, items=items, summary=summary, tool="check.sh (로컬 설치형)", totals=totals), open(os.path.join(a.out, "report.json"), "w"), ensure_ascii=False, indent=2)
    cls = lambda r: r.replace(" ", "-")
    srows = "".join(f"<tr><td>{esc(c)}</td><td>{s['total']}</td><td>{s['ok']}</td><td>{s['vuln']}</td><td>{s['unknown']}</td><td>{s['na']}</td><td><b>{s['rate']*100:.1f}%</b></td></tr>" for c, s in summary.items())
    srows += f"<tr><th>전체</th><th>{tot}</th><th>{tot-vul-totals['unknown']}</th><th>{vul}</th><th>{totals['unknown']}</th><th></th><th>{totals['rate']*100:.1f}%</th></tr>"
    irows = "".join(f"<tr><td>{esc(i['id'])}</td><td>{esc(i['category'])}</td><td>{esc(i['name'])}</td><td>{esc(i['grade'])}</td><td class={cls(i['result'])}>{esc(i['result'])}</td><td class=ev>{esc(i['evidence'])}</td></tr>" for i in items)
    imp = "미이행" if vul else ("일부 확인 불가" if totals["unknown"] else "이행")
    summ = f"점검 {tot}개 중 취약 {vul}개(취약률 {totals['rate']*100:.1f}%), 확인 불가 {totals['unknown']}개. 확인 불가는 안전하다는 뜻이 아니므로 권한을 갖춰 재점검해야 한다."
    open(os.path.join(a.out, "report.html"), "w").write(page("점검 결과서", f"""<h1>리눅스 보안 점검 결과서</h1><p>호스트 <b>{esc(host)}</b> · 점검 루트 <code>{esc(a.root)}</code> · {esc(now)} · 읽기 전용 로컬 점검</p>
<h2>1. 점검 항목표와 결과</h2><table><tr><th>ID</th><th>분류</th><th>항목</th><th>등급</th><th>판정</th><th>근거</th></tr>{irows}</table>
<h2>2. 분야별 취약률 <small>(취약 ÷ (양호+취약+확인 불가), 해당 없음 제외)</small></h2><table><tr><th>분야</th><th>점검 항목 수</th><th>양호</th><th>취약</th><th>확인 불가</th><th>해당 없음</th><th>취약률</th></tr>{srows}</table>
<h2>3. 결과표</h2><table><tr><th>관점</th><th>내용</th><th>이행 여부</th></tr>
<tr><td>관리적 관점</td><td>정보보호 정책 등은 인터뷰 대상이며 이 도구는 점검하지 않음</td><td>미점검</td></tr>
<tr><td>기술적 관점</td><td>서버 설정 {tot}개 항목 로컬 점검</td><td>{imp}</td></tr>
<tr><td>총평</td><td colspan=2>{esc(summ)}</td></tr></table>"""))
    print(f"{summ}\n결과: {a.out}/report.html, report.json, assets.html, assets.json")
main()
