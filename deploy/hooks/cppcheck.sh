#!/usr/bin/env bash
# Example post_edit / pre_proposal hook: static analysis of changed C/C++
# files with cppcheck. Install at a root-owned path and reference it from
# the policy, e.g. "hooks": {"post_edit": ["/opt/govcode/hooks/cppcheck.sh"]}.
# govcode runs it in the sandbox with GOVCODE_CHANGED_FILES set.
set -euo pipefail
files=()
for f in $GOVCODE_CHANGED_FILES; do
  case "$f" in *.c|*.h|*.cc|*.cpp|*.hpp|*.cxx) files+=("$f") ;; esac
done
[ ${#files[@]} -eq 0 ] && exit 0
exec cppcheck --quiet --error-exitcode=1 --enable=warning,portability --inline-suppr "${files[@]}"
