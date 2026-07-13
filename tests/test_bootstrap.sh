#!/bin/bash
# Tests for setup/bootstrap.sh — the curl|bash installer entry point.
#
# Checks that the script's pinned TAG actually exists on the repository it
# clones from, and that a failed clone reports an error instead of dying
# silently (see issue #11).
#
# The clone-failure test runs bootstrap.sh as root inside a throwaway
# ubuntu:22.04 container; it is skipped if docker is unavailable.

set -u

BOOTSTRAP="$(cd "$(dirname "$0")/.." && pwd)/setup/bootstrap.sh"
FAILURES=0

fail() {
	echo "FAIL: $1"
	FAILURES=$((FAILURES+1))
}

pass() {
	echo "ok:   $1"
}

# 1. The script must parse.
if bash -n "$BOOTSTRAP"; then
	pass "bootstrap.sh has valid syntax"
else
	fail "bootstrap.sh has a syntax error"
fi

# 2. The default TAG must exist on the default SOURCE, or every
#    curl|bash install fails at the clone step. The first TAG= line is
#    the one status_checks.py reads, so parse the same way.
TAG=$(grep -m1 -E '^[[:space:]]*TAG=' "$BOOTSTRAP" | sed 's/.*TAG=//')
SOURCE=$(grep -m1 -E '^[[:space:]]*SOURCE=' "$BOOTSTRAP" | sed 's/.*SOURCE=//')
echo "      (default TAG=$TAG SOURCE=$SOURCE)"
if [ -z "$TAG" ] || [ -z "$SOURCE" ]; then
	fail "could not parse default TAG/SOURCE from bootstrap.sh"
elif [ -n "$(git ls-remote --tags "$SOURCE" "refs/tags/$TAG")" ]; then
	pass "tag $TAG exists on $SOURCE"
else
	fail "tag $TAG does not exist on $SOURCE — bootstrap.sh clone will fail"
fi

# 3. A failed clone must exit non-zero and say what went wrong.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	OUTPUT=$(docker run --rm -v "$BOOTSTRAP:/bootstrap.sh:ro" -e TAG=v0.0-nonexistent-tag ubuntu:22.04 bash /bootstrap.sh 2>&1)
	STATUS=$?
	if [ $STATUS -eq 0 ]; then
		fail "bootstrap.sh exited 0 despite an impossible clone"
	else
		pass "bootstrap.sh exits non-zero when the clone fails"
	fi
	if echo "$OUTPUT" | grep -qi "failed to download"; then
		pass "bootstrap.sh reports the clone failure"
	else
		fail "no clone-failure message in output; got: $(echo "$OUTPUT" | tail -3 | tr '\n' ' ')"
	fi
else
	echo "skip: docker unavailable, not testing the clone-failure path"
fi

echo
if [ $FAILURES -gt 0 ]; then
	echo "$FAILURES test(s) failed."
	exit 1
fi
echo "All tests passed."
