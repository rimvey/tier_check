#!/usr/bin/env bash
# 2장 리눅스 보안 점검기 (로컬 설치형). 읽기 전용: 시스템 파일을 수정하지 않는다. SPEC.md 2절 규칙 구현.
# 사용: check.sh [--root DIR] [--out DIR]
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT=/; OUT="$HERE/../out"
while [ $# -gt 0 ]; do
  case "$1" in --root) ROOT="$2"; shift 2;; --out) OUT="$2"; shift 2;; *) echo "알 수 없는 옵션: $1" >&2; exit 2;; esac
done
ROOT="${ROOT%/}"; R="$ROOT"                    # R 은 경로 접두어 ("/" 이면 빈 문자열)
[ -z "$ROOT" ] && ROOT=/
mkdir -p "$OUT"; TSV="$OUT/items.tsv"; : > "$TSV"
if [ -z "$R" ]; then ROOT_UID=0; else ROOT_UID=$(stat -c %u "$ROOT"); fi   # 2-0(c)

rec() { # id cat name grade result evidence
  local ev="${6//$'\n'/ | }"; ev="${ev//$'\t'/ }"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$ev" >> "$TSV"
}
fstate() { # ok | unreadable | missing  (1-7, 2-0b)
  local f="$1" d
  if [ -e "$f" ]; then [ -r "$f" ] && echo ok || echo unreadable; return; fi
  d="$(dirname "$f")"
  if [ -e "$d" ] && [ ! -x "$d" ]; then echo unreadable; else echo missing; fi
}
kv() { # 마지막 유효 줄: "값<TAB>줄번호"  (2-0a)
  awk -v k="$2" '{l=$0; sub(/#.*/,""); gsub(/=/," "); if(NF>=2 && tolower($1)==tolower(k)){v=$2;n=NR;t=l}} END{if(v!="")print v "\t" n "\t" t}' "$1" 2>/dev/null
}
valid() { grep -nvE '^[[:space:]]*(#|$)' "$1" 2>/dev/null; }   # 주석·빈 줄 제외 (줄번호 포함)
oct_within() { (( (8#$1 & ~8#$2) == 0 )); }                   # 2-0(d)

if [ -z "$R" ]; then PS_TXT=$(ps -ef 2>/dev/null); PORTS_TXT=$(ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null)
else PS_TXT=$(cat "$ROOT/ps.txt" 2>/dev/null); PORTS_TXT=$(cat "$ROOT/ports.txt" 2>/dev/null); fi
open_ports() { # proto_regex port... → 열린 포트 목록
  local pr="$1" p out=""; shift
  for p in "$@"; do grep -E "^($pr)" <<<"$PORTS_TXT" | grep -Eq ":$p[[:space:]]" && out+="$p "; done
  echo "${out% }"
}

# ---------------- 계정 관리 ----------------
CAT=계정\ 관리

# U-01 (2-1)
SSH_VAL=""; SSH_EV=""; SSH_STOP=0; SSH_COMM=""
ssh_scan() {
  local f="$1" depth="$2" n=0 line t key w pat g
  [ "$depth" -gt 5 ] && return
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n+1)); [ "$SSH_STOP" = 1 ] && return
    t="${line#"${line%%[![:space:]]*}"}"
    case "$t" in
      ''|'#'*) [[ "$t" =~ ^#[[:space:]]*PermitRootLogin ]] && SSH_COMM+="$f:$n: $t; "; continue;;
    esac
    read -ra w <<<"$t"; key="${w[0],,}"
    case "$key" in
      include) for pat in "${w[@]:1}"; do case "$pat" in /*) pat="$R$pat";; *) pat="$R/etc/ssh/$pat";; esac
                 for g in $pat; do [ -f "$g" ] && [ -r "$g" ] && ssh_scan "$g" $((depth+1)); done; done;;
      match) SSH_STOP=1; return;;
      permitrootlogin) [ -z "$SSH_VAL" ] && { SSH_VAL="${w[1],,}"; SSH_EV="$f:$n: $t"; };;
    esac
  done < "$f"
}
f="$R/etc/ssh/sshd_config"; st=$(fstate "$f")
case $st in
  missing) rec U-01 "$CAT" "root 원격 접속 제한" 상 "해당 없음" "$f 없음(sshd 미설치)";;
  unreadable) rec U-01 "$CAT" "root 원격 접속 제한" 상 "확인 불가" "$f 읽기 권한 없음";;
  ok) ssh_scan "$f" 0
      if [ "$SSH_VAL" = no ]; then rec U-01 "$CAT" "root 원격 접속 제한" 상 양호 "$SSH_EV"
      elif [ -n "$SSH_VAL" ]; then rec U-01 "$CAT" "root 원격 접속 제한" 상 취약 "$SSH_EV (값이 no 가 아님)"
      else rec U-01 "$CAT" "root 원격 접속 제한" 상 취약 "유효한 PermitRootLogin 줄 없음. ${SSH_COMM:+주석 처리됨: $SSH_COMM}기본값 적용(prohibit-password)이므로 no 가 아님";fi;;
esac

# U-02 (2-2)
pam_ml=""; pam_mc=""; pam_found=""; unread=""; ev=""
for p in common-password system-auth password-auth; do
  f="$R/etc/pam.d/$p"; st=$(fstate "$f"); [ "$st" = unreadable ] && unread+="$f "
  [ "$st" = ok ] || continue
  l=$(valid "$f" | grep -E 'pam_(pwquality|cracklib)\.so' | tail -1)
  if [ -n "$l" ]; then pam_found="$f"; ev+="$f:$l; "
    v=$(grep -oE 'minlen=-?[0-9]+' <<<"$l" | tail -1); pam_ml="${v#minlen=}"
    v=$(grep -oE 'minclass=[0-9]+' <<<"$l" | tail -1); pam_mc="${v#minclass=}"; break; fi
done
ml=""; mc=""
if [ -n "$pam_found" ]; then
  f="$R/etc/security/pwquality.conf"; st=$(fstate "$f")
  if [ "$st" = ok ]; then
    r=$(kv "$f" minlen); [ -n "$r" ] && { cml="${r%%$'\t'*}"; ev+="$f minlen=$cml; "; }
    r=$(kv "$f" minclass); [ -n "$r" ] && { cmc="${r%%$'\t'*}"; ev+="$f minclass=$cmc; "; }
  elif [ "$st" = unreadable ]; then unread+="$f "; fi
  ml="${pam_ml:-${cml:-}}"; mc="${pam_mc:-${cmc:-}}"
  need=""; [ -z "$ml" ] && { ml=8; need=1; }; [ -z "$mc" ] && { mc=0; need=1; }
  ev+="(없는 값은 기본값 minlen 8, minclass 0)"
  if [ -n "$need" ] && [ "$st" = unreadable ]; then rec U-02 "$CAT" "패스워드 복잡성 설정" 상 "확인 불가" "$f 읽기 불가. $ev"; skip=1; fi
else
  f="$R/etc/login.defs"; st=$(fstate "$f")
  if [ "$st" = ok ]; then r=$(kv "$f" PASS_MIN_LEN); ml="${r%%$'\t'*}"; ml="${ml:-0}"; ev="pam_pwquality 줄 없음, $f PASS_MIN_LEN=${ml}, minclass 제한 없음(0)"; mc=0
  elif [ "$st" = unreadable ] || [ -n "$unread" ]; then rec U-02 "$CAT" "패스워드 복잡성 설정" 상 "확인 불가" "읽지 못한 파일: $unread$f"; skip=1
  else ml=0; mc=0; ev="pam_pwquality 줄 없음, login.defs 없음 → 제한 없음"; fi
fi
if [ -z "$skip" ]; then
  if { [ "$ml" -ge 8 ] && [ "$mc" -ge 3 ]; } || { [ "$ml" -ge 10 ] && [ "$mc" -ge 2 ]; }; then rec U-02 "$CAT" "패스워드 복잡성 설정" 상 양호 "minlen=$ml minclass=$mc. $ev"
  else rec U-02 "$CAT" "패스워드 복잡성 설정" 상 취약 "minlen=$ml minclass=$mc (3종 8자 또는 2종 10자 미달). $ev"; fi
fi
skip=""

# U-03 (2-3)
files=""; unread=""; lockline=""
if [ ! -d "$R/etc/pam.d" ] && [ ! -e "$R/etc/security/faillock.conf" ]; then
  rec U-03 "$CAT" "계정 잠금 임계값 설정" 상 "해당 없음" "/etc/pam.d, faillock.conf 없음(PAM 미사용)"
else
  for p in common-auth system-auth password-auth login sshd; do
    f="$R/etc/pam.d/$p"; st=$(fstate "$f"); [ "$st" = unreadable ] && unread+="$f "
    [ "$st" = ok ] || continue
    l=$(valid "$f" | grep -E 'pam_(faillock|tally2|tally)\.so' | head -1)
    [ -n "$l" ] && { lockline="$f:$l"; break; }
  done
  if [ -z "$lockline" ]; then
    if [ -n "$unread" ]; then rec U-03 "$CAT" "계정 잠금 임계값 설정" 상 "확인 불가" "읽지 못한 PAM 파일: $unread"
    else rec U-03 "$CAT" "계정 잠금 임계값 설정" 상 취약 "PAM 에 pam_faillock/pam_tally2 줄 없음(faillock.conf 만으로는 적용되지 않음)"; fi
  else
    v=$(grep -oE 'deny=[0-9]+' <<<"$lockline" | tail -1); v="${v#deny=}"; src="PAM 인자"
    if [ -z "$v" ]; then f="$R/etc/security/faillock.conf"
      if [ "$(fstate "$f")" = ok ]; then r=$(kv "$f" deny); v="${r%%$'\t'*}"; [ -n "$v" ] && src="$f"; fi
    fi
    [ -z "$v" ] && { v=3; src="pam_faillock 기본값"; }
    if [ "$v" -ge 1 ] && [ "$v" -le 10 ]; then rec U-03 "$CAT" "계정 잠금 임계값 설정" 상 양호 "$lockline ; deny=$v ($src)"
    else rec U-03 "$CAT" "계정 잠금 임계값 설정" 상 취약 "$lockline ; deny=$v ($src), 1~10 아님"; fi
  fi
fi

# U-04 (2-4)
f="$R/etc/passwd"; st=$(fstate "$f"); PASSWD_ST=$st
if [ "$st" != ok ]; then rec U-04 "$CAT" "root 이외 UID 0 금지" 중 "확인 불가" "$f 읽을 수 없음($st)"
else n=$(awk -F: '$3==0{print $1}' "$f" | tr '\n' ' ')
  if [ "$(wc -w <<<"$n")" -le 1 ]; then rec U-04 "$CAT" "root 이외 UID 0 금지" 중 양호 "$f 3번째 필드 UID 0 계정: $n"
  else rec U-04 "$CAT" "root 이외 UID 0 금지" 중 취약 "UID 0 계정: $n"; fi; fi

# U-05 (2-5)
if [ "$PASSWD_ST" != ok ]; then rec U-05 "$CAT" "불필요 계정 제거" 하 "확인 불가" "$R/etc/passwd 읽을 수 없음"
else bad=$(awk -F: '$1~/^(lp|uucp|nuucp|games|news|gopher)$/ && $7!~/(nologin|false|sync|halt|shutdown)$/ {print $1"("($7==""?"빈 셸":$7)")"}' "$R/etc/passwd" | tr '\n' ' ')
  exist=$(awk -F: '$1~/^(lp|uucp|nuucp|games|news|gopher)$/{print $1}' "$R/etc/passwd" | tr '\n' ' ')
  if [ -z "$bad" ]; then rec U-05 "$CAT" "불필요 계정 제거" 하 양호 "대상 계정 중 존재: ${exist:-없음}, 로그인 셸 가진 계정 없음"
  else rec U-05 "$CAT" "불필요 계정 제거" 하 취약 "로그인 셸이 있는 계정: $bad"; fi; fi

# U-06 (2-6)
f="$R/etc/login.defs"; st=$(fstate "$f")
if [ "$st" != ok ]; then rec U-06 "$CAT" "패스워드 최대 사용기간" 중 "확인 불가" "$f 읽을 수 없음($st)"
else r=$(kv "$f" PASS_MAX_DAYS); v="${r%%$'\t'*}"
  if [ -z "$v" ]; then rec U-06 "$CAT" "패스워드 최대 사용기간" 중 취약 "$f 에 유효한 PASS_MAX_DAYS 없음 → 기본값 99999"
  else ln=$(cut -f2 <<<"$r"); if [ "$v" -ge 1 ] && [ "$v" -le 90 ]; then rec U-06 "$CAT" "패스워드 최대 사용기간" 중 양호 "$f:$ln PASS_MAX_DAYS $v"
  else rec U-06 "$CAT" "패스워드 최대 사용기간" 중 취약 "$f:$ln PASS_MAX_DAYS $v (1~90 아님)"; fi; fi; fi

# U-07 (2-7) 해시 값은 근거에 쓰지 않는다
f="$R/etc/shadow"; st=$(fstate "$f"); NAME="패스워드 파일 보호(shadow 내용)"
if [ "$st" = unreadable ]; then rec U-07 "$CAT" "$NAME" 상 "확인 불가" "$f 읽기 권한 없음(권한 부족 → 양호 아님)"
elif [ "$st" = missing ]; then
  if [ "$PASSWD_ST" = ok ] && awk -F: '$2!="x" && $2!="" && $2!="*" && $2!="!"{f=1} END{exit !f}' "$R/etc/passwd"; then rec U-07 "$CAT" "$NAME" 상 취약 "shadow 없음, /etc/passwd 2번째 필드에 해시 있음(shadow 미사용)"
  else rec U-07 "$CAT" "$NAME" 상 "확인 불가" "$f 없음"; fi
else
  empty=$(awk -F: '$2==""{print $1}' "$f" | tr '\n' ' ')
  weak=$(awk -F: '$2!="" && $2!~/^[*!]/ && $2!~/^\$(6|5|y|gy|7|2[abxy]?)\$/ {print $1}' "$f" | tr '\n' ' ')
  cnt=$(awk -F: '$2!="" && $2!~/^[*!]/' "$f" | wc -l)
  algs=$(awk -F: '$2!="" && $2!~/^[*!]/{ if($2~/^\$/){split($2,a,"$"); print "$" a[2] "$"} else print "DES(추정)"}' "$f" | sort | uniq -c | tr '\n' ' ')
  if [ -n "$empty" ] || [ -n "$weak" ]; then rec U-07 "$CAT" "$NAME" 상 취약 "빈 비밀번호 계정: ${empty:-없음}; 약한 해시 계정: ${weak:-없음}"
  else rec U-07 "$CAT" "$NAME" 상 양호 "해시 보유 계정 ${cnt}개, 알고리즘: ${algs:-해시 없음}, 빈 비밀번호 없음"; fi
fi

# ---------------- 서비스 관리 ----------------
CAT=서비스\ 관리
# 공통 스캔 (1-9, 2-8, 2-10, 2-12): names inetd_re proc_re proto_re ports
SV_PRESENT=0; SV_BAD=0; SV_UNREAD=0; SV_EV=""
svc_scan() {
  local names="$1" ire="$2" pre="$3" proto="$4" ports="$5" n f g st d l pl op
  SV_PRESENT=0; SV_BAD=0; SV_UNREAD=0; SV_EV=""
  for n in $names; do for g in "$R"/etc/xinetd.d/$n*; do
    [ -e "$g" ] || { [ "$(fstate "$g")" = unreadable ] && { SV_UNREAD=1; SV_EV+="$g 읽기 불가; "; }; continue; }
    SV_PRESENT=1; st=$(fstate "$g")
    if [ "$st" != ok ]; then SV_UNREAD=1; SV_EV+="$g 읽기 불가; "; continue; fi
    d=$(kv "$g" disable); l="${d%%$'\t'*}"
    if [ "$l" = yes ]; then SV_EV+="$g disable = yes; "
    else SV_BAD=1; SV_EV+="$g disable=${l:-(줄 없음→기본값 no, 활성)}; "; fi
  done; done
  f="$R/etc/inetd.conf"; st=$(fstate "$f")
  if [ "$st" = unreadable ]; then SV_UNREAD=1; SV_EV+="$f 읽기 불가; "
  elif [ "$st" = ok ]; then l=$(valid "$f" | grep -E "^[0-9]+:$ire" | head -1)
    [ -n "$l" ] && { SV_PRESENT=1; SV_BAD=1; SV_EV+="$f:$l; "; }; fi
  pl=$(grep -E "$pre" <<<"$PS_TXT" | grep -v grep | head -2 | tr '\n' ' ')
  [ -n "$pl" ] && { SV_PRESENT=1; SV_BAD=1; }
  SV_EV+="[ps -ef] ${pl:-해당 프로세스 없음}; "
  op=$(open_ports "$proto" $ports)
  [ -n "$op" ] && { SV_PRESENT=1; SV_BAD=1; }
  SV_EV+="[ports ${ports// /,}] ${op:+열림: $op}${op:-닫힘}"
}
svc_ev_services() { local f="$R/etc/services"; [ -r "$f" ] && { local l; l=$(grep -E "^($1)[[:space:]]" "$f" | head -1); echo "[/etc/services] ${l:-정의 없음}; "; }; }
svc_rec() { # id name grade  (취약 > 확인 불가 > 해당 없음 > 양호)
  local pre="$4"
  if [ $SV_BAD = 1 ]; then rec "$1" "$CAT" "$2" "$3" 취약 "$pre$SV_EV"
  elif [ $SV_UNREAD = 1 ]; then rec "$1" "$CAT" "$2" "$3" "확인 불가" "$pre$SV_EV"
  elif [ $SV_PRESENT = 0 ]; then rec "$1" "$CAT" "$2" "$3" "해당 없음" "$pre설치 징후 없음. $SV_EV"
  else rec "$1" "$CAT" "$2" "$3" 양호 "$pre$SV_EV"; fi
}

# S-01 (2-8)
svc_scan "finger" "finger[[:space:]]" "fingerd" "tcp" "79"; svc_rec S-01 "Finger 서비스 비활성화" 상 "$(svc_ev_services finger)"

# S-02 (2-9)
f=""; for c in "$R/etc/vsftpd.conf" "$R/etc/vsftpd/vsftpd.conf"; do [ "$(fstate "$c")" != missing ] && { f="$c"; break; }; done
p21=$(open_ports "tcp" 21)
if [ -z "$f" ]; then
  if [ -n "$p21" ]; then rec S-02 "$CAT" "Anonymous FTP 비활성화" 상 "확인 불가" "vsftpd.conf 없음, 21 포트 열림(어떤 FTP 서버인지 확인 못 함)"
  else rec S-02 "$CAT" "Anonymous FTP 비활성화" 상 "해당 없음" "vsftpd.conf 없음, 21 포트 닫힘(FTP 서버 미설치)"; fi
elif [ "$(fstate "$f")" = unreadable ]; then rec S-02 "$CAT" "Anonymous FTP 비활성화" 상 "확인 불가" "$f 읽기 불가"
else r=$(kv "$f" anonymous_enable); v="${r%%$'\t'*}"
  if [ "${v^^}" = NO ]; then rec S-02 "$CAT" "Anonymous FTP 비활성화" 상 양호 "$f:$(cut -f2 <<<"$r") anonymous_enable=NO"
  else rec S-02 "$CAT" "Anonymous FTP 비활성화" 상 취약 "$f anonymous_enable=${v:-(줄 없음 → vsftpd 기본값 YES)}"; fi; fi

# S-03 (2-10)
svc_scan "rsh rlogin rexec" "(shell|login|exec)[[:space:]]" "rshd|rlogind|rexecd|in\.r(sh|login|exec)d" "tcp" "512 513 514"
if [ $SV_PRESENT = 1 ] && [ $SV_BAD = 0 ]; then
  for g in "$R/etc/hosts.equiv" "$R/root/.rhosts" "$R"/home/*/.rhosts; do
    [ "$(fstate "$g")" = ok ] || { [ -e "$g" ] && { SV_UNREAD=1; SV_EV+="; $g 읽기 불가"; }; continue; }
    if grep -qE '^[[:space:]]*\+' "$g"; then SV_BAD=1; SV_EV+="; $g 에 '+' 있음"; fi
  done
  for d in "$R"/home/*/; do [ -d "$d" ] && [ ! -x "$d" ] && { SV_UNREAD=1; SV_EV+="; $d 접근 불가(.rhosts 확인 못 함)"; }; done
fi
svc_rec S-03 "r 계열 서비스 비활성화" 상 "$(svc_ev_services 'shell|login|exec')"

# S-04 (2-11)
f="$R/etc/exports"; st=$(fstate "$f")
nfs=$(grep -E 'nfsd|rpc\.mountd' <<<"$PS_TXT" | grep -v grep | head -1); p2049=$(open_ports "tcp|udp" 2049)
if [ "$st" = unreadable ]; then rec S-04 "$CAT" "NFS 접근 통제" 상 "확인 불가" "$f 읽기 불가"
elif [ "$st" = missing ]; then
  if [ -z "$nfs" ] && [ -z "$p2049" ]; then rec S-04 "$CAT" "NFS 접근 통제" 상 "해당 없음" "exports 없음, nfsd 프로세스·2049 포트 없음"
  else rec S-04 "$CAT" "NFS 접근 통제" 상 양호 "exports 없음 → 공유 항목 없음 (nfsd 실행: ${nfs:-없음}, 2049: ${p2049:-닫힘})"; fi
else
  bad=$(valid "$f" | awk -F: '{ln=$1; sub(/^[0-9]+:/,""); n=split($0,t,/[[:space:]]+/); if(t[1]=="")k=2;else k=1; if(n-k<1){print ln": 클라이언트 제한 없음 → "$0} else for(i=k+1;i<=n;i++){ if(t[i]=="")continue; if(t[i]~/^\*/ || t[i]~/^\(/) print ln": 모든 호스트 → "$0; if(t[i]~/no_root_squash/) print ln": no_root_squash → "$0}}')
  if [ -n "$bad" ]; then rec S-04 "$CAT" "NFS 접근 통제" 상 취약 "$f $(tr '\n' ';' <<<"$bad")"
  else rec S-04 "$CAT" "NFS 접근 통제" 상 양호 "$f 유효 줄 $(valid "$f" | wc -l)개, 모두 호스트 제한·no_root_squash 없음"; fi
fi

# S-05 (2-12)
svc_scan "echo discard daytime chargen" "(echo|discard|daytime|chargen)[[:space:]]" "in\.(echo|discard|daytime|chargen)d" "tcp|udp" "7 9 13 19"
svc_rec S-05 "DoS 공격에 취약한 서비스 비활성화" 상 "$(svc_ev_services 'echo|discard|daytime|chargen')"

# ---------------- 파일 시스템 ----------------
CAT=파일\ 시스템
perm_item() { # id path max name grade
  local f="$R$2" st p o g
  st=$(fstate "$f")
  if [ ! -e "$f" ] || ! stat -c %a "$f" >/dev/null 2>&1; then rec "$1" "$CAT" "$4" "$5" "확인 불가" "$f stat 실패($st)"; return; fi
  p=$(stat -c %a "$f"); o=$(stat -c %u "$f"); g=$(stat -c '%U:%G' "$f")
  if [ "$o" = "$ROOT_UID" ] && oct_within "$p" "$3"; then rec "$1" "$CAT" "$4" "$5" 양호 "stat $f → 권한 $p, 소유 $g (기준 $3 이하, 소유자 root)"
  else rec "$1" "$CAT" "$4" "$5" 취약 "stat $f → 권한 $p, 소유 $g (기준: root, $3 이하)"; fi
}
perm_item F-01 /etc/passwd 644 "/etc/passwd 파일 소유자 및 권한" 상
perm_item F-02 /etc/shadow 600 "/etc/shadow 파일 소유자 및 권한" 상
perm_item F-03 /etc/hosts 644 "/etc/hosts 파일 소유자 및 권한" 상

# F-04 (2-16)
ALLOW="$HERE/suid_allowlist.txt"; errf=$(mktemp)
if [ -z "$R" ]; then found=$(find -H /bin /sbin /lib /lib64 /usr /opt -xdev -type f -perm /6000 -printf '%p %m\n' 2>"$errf")
else found=$(find "$ROOT" -type f -perm /6000 -printf '%p %m\n' 2>"$errf"); fi
found=$(while read -r a b; do [ -n "$a" ] && echo "$(readlink -f "$a") $b"; done <<<"$found" | sort -u)
unreadable_dirs=$(grep -c . "$errf"); rm -f "$errf"
bad=""; while IFS= read -r l; do [ -z "$l" ] && continue; b=$(basename "${l% *}")
  grep -qxF "$b" <(grep -vE '^[[:space:]]*(#|$)' "$ALLOW") || bad+="$l; "; done <<<"$found"
if [ -n "$bad" ]; then rec F-04 "$CAT" "불필요한 SUID·SGID 파일" 상 취약 "허용 목록 밖 SUID/SGID: $bad"
elif [ "$unreadable_dirs" -gt 0 ]; then rec F-04 "$CAT" "불필요한 SUID·SGID 파일" 상 "확인 불가" "검색 중 접근 불가 경로 ${unreadable_dirs}곳, 허용 목록 밖 파일은 찾지 못함"
else rec F-04 "$CAT" "불필요한 SUID·SGID 파일" 상 양호 "find -perm /6000 결과 $(grep -c . <<<"$found")개 모두 허용 목록(src/suid_allowlist.txt) 안"; fi

# F-05 (2-17)
vals=""; weak=""; ev=""; lu=0
f="$R/etc/login.defs"; st=$(fstate "$f")
if [ "$st" = ok ]; then r=$(kv "$f" UMASK); [ -n "$r" ] && { v="${r%%$'\t'*}"; vals+="$v "; ev+="$f UMASK $v; "; (( (8#$v & 8#022) != 8#022 )) && weak+="$f($v) "; }
elif [ "$st" = unreadable ]; then lu=1; fi
for f in "$R/etc/profile" "$R/etc/bash.bashrc" "$R"/etc/profile.d/*.sh "$R/etc/csh.cshrc" "$R/etc/csh.login"; do
  [ "$(fstate "$f")" = ok ] || continue
  while IFS= read -r l; do v=$(grep -oE 'umask[[:space:]]+[0-7]+' <<<"$l" | awk '{print $2}' | tail -1)
    [ -n "$v" ] && { vals+="$v "; ev+="$f: $l; "; (( (8#$v & 8#022) != 8#022 )) && weak+="$f($v) "; }
  done < <(valid "$f" | sed -E 's/^[0-9]+://')
done
if [ -n "$weak" ]; then rec F-05 "$CAT" "UMASK 설정" 중 취약 "022 미만(약한) 값: $weak"
elif [ -z "$vals" ]; then
  if [ $lu = 1 ]; then rec F-05 "$CAT" "UMASK 설정" 중 "확인 불가" "login.defs 읽기 불가, 다른 파일에서 umask 못 찾음"
  else rec F-05 "$CAT" "UMASK 설정" 중 취약 "UMASK 설정을 찾지 못함"; fi
else rec F-05 "$CAT" "UMASK 설정" 중 양호 "$ev"; fi

# F-06 (2-18)
bad=""; ev=""; unr=""
[ -d "$R/root" ] && [ ! -x "$R/root" ] && unr="$R/root 접근 불가"
for f in "$R/root/.bashrc" "$R/root/.profile" "$R/root/.bash_profile" "$R/root/.cshrc" "$R/etc/profile" "$R/etc/bash.bashrc" "$R/etc/environment"; do
  st=$(fstate "$f"); [ "$st" = unreadable ] && { unr+=" $f 읽기 불가"; continue; }; [ "$st" = ok ] || continue
  while IFS= read -r l; do
    ln="${l%%:*}"; body="${l#*:}"
    p=$(sed -nE 's/^[[:space:]]*(export[[:space:]]+)?(PATH|setenv[[:space:]]+PATH)[=[:space:]]+//p' <<<"$body" | tr -d "\"'")
    [ -z "$p" ] && continue; ev+="$f:$ln PATH=$p; "
    IFS=: read -ra els <<<"$p:x"; unset 'els[${#els[@]}-1]'
    for e in "${els[@]}"; do [ "$e" = . ] || [ -z "$e" ] && { bad+="$f:$ln ($p); "; break; }; done
  done < <(valid "$f")
done
if [ -n "$bad" ]; then rec F-06 "$CAT" "root 홈·PATH 에 \".\" 금지" 상 취약 "PATH 에 '.' 또는 빈 요소: $bad"
elif [ -n "$unr" ]; then rec F-06 "$CAT" "root 홈·PATH 에 \".\" 금지" 상 "확인 불가" "$unr"
else rec F-06 "$CAT" "root 홈·PATH 에 \".\" 금지" 상 양호 "${ev:-PATH 설정 줄 없음}"; fi

# ---------------- 결과 렌더링 ----------------
python3 -I "$HERE/render.py" --tsv "$TSV" --out "$OUT" --root "$ROOT"
