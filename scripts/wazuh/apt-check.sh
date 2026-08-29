#!/bin/bash
if [ -x /usr/lib/update-notifier/apt-check ]; then
  /usr/lib/update-notifier/apt-check 2>&1
else
  count=$(apt list --upgradable 2>/dev/null | tail -n +2 | grep -c .)
  security=$(apt list --upgradable 2>/dev/null | grep -c -- '-security')
  [ -z "$count" ] && count=0
  [ -z "$security" ] && security=0
  echo "${count};${security}"
fi
