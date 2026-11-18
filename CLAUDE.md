# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

이 프로젝트는 읽기전용 점검도구다. sudo와 시스템 파일 수정은 하지 않는다.

Repo: https://github.com/rimvey/tier_check

## 개요
교재 2장 "리눅스 보안 점검기: 내 PC 진단". 판정 규칙의 단일 출처는 `SPEC.md` 이며, 코드는 SPEC.md 에 적힌 규칙만 구현한다(규칙을 바꾸려면 SPEC.md 를 먼저 고친다). 항목 ID(U-01~F-06)와 절 번호(2-1~2-18)로 코드와 SPEC 을 대응시킨다.

## 구조 (로컬 설치형, SPEC 1-6)
- `src/check.sh` — 점검 스크립트. `--root <dir>`(기본 `/`)로 점검 루트를 바꾼다. 테스트 루트에서는 명령 대신 `<root>/ps.txt`, `<root>/ports.txt` 를 읽고, 소유자 기준도 루트 디렉터리 소유자로 바뀐다(SPEC 2-0c). 항목 결과를 TSV 로 `out/` 에 쓴 뒤 `src/render.py` 를 호출한다.
- `src/render.py` — TSV → `out/report.json`(취약률 계산식 SPEC 1-8, 해당 없음은 분모 제외) + `out/report.html`.
- `src/suid_allowlist.txt` — F-04 허용 목록(파일 이름 기준).
- `assets.json` / `assets.html` — 자산 관리 대장(SPEC 1-1~1-3). `out/assets.json` 형식은 SPEC 4절이며 9장이 읽는다.
- `tests/` — 픽스처 루트로 `--root` 를 돌리는 함정 테스트(SPEC 3절).

## 명령
```
bash src/check.sh                      # 현재 PC 점검 (비root 면 U-07 등이 확인 불가가 되는 것이 정상)
bash src/check.sh --root tests/fx/xxx  # 픽스처 루트 점검
python3 -m http.server 8000 --directory out   # 결과 확인용 서버
```

## 판정 원칙 (코드 전반에 걸침)
- 판정 4종: 양호 / 취약 / 확인 불가 / 해당 없음. 읽지 못하면 반드시 확인 불가이며 양호로 적지 않는다.
- `#` 주석은 설정이 아니다. 설정이 없으면 기본값이 적용되므로 취약일 수 있다(근거에 "주석 처리됨"·"기본값" 명시).
- 중복 키: sshd 는 첫 유효 줄, 그 외 key=value 파일은 마지막 유효 줄.
- 근거(evidence)에 shadow 해시 값은 쓰지 않는다.
