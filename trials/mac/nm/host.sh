#!/bin/sh
# Trial native host: records how Chrome started it, then answers one message.
LOG="${PHANTAB_NM_LOG:-/tmp/phantab-mac/nm-host.log}"
{
  echo "argc=$#"
  i=0; for a in "$0" "$@"; do echo "argv[$i]=$a"; i=$((i+1)); done
  echo "cwd=$(pwd)"
  echo "ppid=$PPID parent=$(ps -o comm= -p $PPID)"
  echo "stdin_is_pipe=$([ -p /dev/stdin ] && echo yes || echo no)"
} > "$LOG"
head -c 4 >/dev/null   # drop the request length; the body is ignored
printf '\010\000\000\000{"ok":1}'
