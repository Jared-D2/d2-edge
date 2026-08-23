#!/usr/bin/env python3
"""Minimal AT command sender for the SIM7600 (no pyserial dependency).

Usage: oob-at.py '<AT command>' [device]   (device default /dev/d2-modem)
Prints the raw response; exits non-zero if the port can't be opened or is
busy. All callers (watchdog, setup-oob, operators) serialise on a lock —
two concurrent opens of the same AT port steal each other's replies
(pilot 2026-08-23: a watchdog probe colliding with setup-oob's AT+CGDCONT?
query made the deploy "set" the APN and AT+CFUN=1,1-reboot the modem).
"""
import fcntl
import os
import sys
import termios
import time

LOCK = "/run/lock/d2-modem.lock"
LOCK_WAIT = 15.0   # > one full probe (2.5 s) × a few queued callers


def send(dev, cmd, wait=2.5):
    lf = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o644)
    deadline = time.monotonic() + LOCK_WAIT
    while True:
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() > deadline:
                os.close(lf)
                sys.exit("oob-at: modem AT port busy (lock held >%ds)" % LOCK_WAIT)
            time.sleep(0.2)
    try:
        fd = os.open(dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            attrs = termios.tcgetattr(fd)
            attrs[0] = attrs[1] = attrs[3] = 0
            attrs[4] = attrs[5] = termios.B115200
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            termios.tcflush(fd, termios.TCIOFLUSH)
            os.write(fd, cmd.encode() + b"\r")
            time.sleep(wait)
            try:
                return os.read(fd, 4096).decode(errors="replace")
            except BlockingIOError:
                return ""
        finally:
            os.close(fd)
    finally:
        os.close(lf)   # releases the flock


if __name__ == "__main__":
    dev = sys.argv[2] if len(sys.argv) > 2 else "/dev/d2-modem"
    print(send(dev, sys.argv[1]).replace("\r", " ").strip())
