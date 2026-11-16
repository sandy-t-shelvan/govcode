#!/usr/bin/env bash
# Example hook: compile changed Ada units with GNAT style and warning
# checks (-gnatwae treats warnings as errors; -gnaty enables style checks).
set -euo pipefail
status=0
for f in $GOVCODE_CHANGED_FILES; do
  case "$f" in *.adb|*.ads) gcc -c -gnatc -gnatwae -gnaty3abcefhiklmnprst "$f" -o /dev/null || status=1 ;; esac
done
exit $status
