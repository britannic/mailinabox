#!/bin/bash
# Unit test for setup/test-mode.sh — runs WITHOUT Docker or a real box.
# Sources functions.sh (for get_default_* helpers) then test-mode.sh in a
# subshell and asserts the exported environment.
set -uo pipefail
cd "$(dirname "$0")/../.."   # repo root
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok: $1"; else echo "FAIL: $1 — expected '$3', got '$2'"; fail=1; fi }
nonempty() { if [ -n "$2" ]; then echo "ok: $1 nonempty ($2)"; else echo "FAIL: $1 empty"; fail=1; fi }

# Case A: flag on, nothing preset — defaults are supplied.
out=$(MIAB_TEST_MODE=1 bash -c '
  source setup/functions.sh >/dev/null 2>&1
  source setup/test-mode.sh >/dev/null 2>&1
  echo "DF=$DISABLE_FIREWALL"; echo "SNC=$SKIP_NETWORK_CHECKS"; echo "NI=$NONINTERACTIVE"
  echo "PIP=$PUBLIC_IP"; echo "PH=$PRIMARY_HOSTNAME"')
check "DISABLE_FIREWALL" "$(sed -n 's/^DF=//p' <<<"$out")" "1"
check "SKIP_NETWORK_CHECKS" "$(sed -n 's/^SNC=//p' <<<"$out")" "1"
check "NONINTERACTIVE" "$(sed -n 's/^NI=//p' <<<"$out")" "1"
nonempty "PUBLIC_IP default" "$(sed -n 's/^PIP=//p' <<<"$out")"
nonempty "PRIMARY_HOSTNAME default" "$(sed -n 's/^PH=//p' <<<"$out")"

# Case B: explicit values win.
out=$(MIAB_TEST_MODE=1 PUBLIC_IP=203.0.113.9 PRIMARY_HOSTNAME=my.box bash -c '
  source setup/functions.sh >/dev/null 2>&1
  source setup/test-mode.sh >/dev/null 2>&1
  echo "PIP=$PUBLIC_IP"; echo "PH=$PRIMARY_HOSTNAME"')
check "PUBLIC_IP explicit wins" "$(sed -n 's/^PIP=//p' <<<"$out")" "203.0.113.9"
check "PRIMARY_HOSTNAME explicit wins" "$(sed -n 's/^PH=//p' <<<"$out")" "my.box"

# Case C: banner is printed to stderr.
berr=$(MIAB_TEST_MODE=1 bash -c 'source setup/functions.sh >/dev/null 2>&1; source setup/test-mode.sh' 2>&1 >/dev/null)
if grep -q "TEST/LAB MODE" <<<"$berr"; then echo "ok: banner printed"; else echo "FAIL: banner missing"; fail=1; fi

exit $fail
