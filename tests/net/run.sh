#!/bin/sh
[ "$(id -u)" -eq 0 ] || exec sudo sh "$0" "$@"
cd "$(dirname "$0")/../.." || exit 1

command -v ip >/dev/null || {
	echo "missing dependency: ip" >&2
	exit 1
}

rc=0
for t in tests/net/t-*.sh; do
	printf '# %s\n' "$t"
	sh "$t" || rc=1
done
exit $rc
