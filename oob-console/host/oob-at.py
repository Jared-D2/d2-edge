#!/usr/bin/env python3
"""Minimal AT command sender for the SIM7600 (no pyserial dependency).

Usage: oob-at.py '<AT command>' [device]   (device default /dev/d2-modem)
Prints the raw response; exits non-zero if the port can't be opened.
"""
import os
import sys
import termios
import time


def send(dev, cmd, wait=2.5):
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


if __name__ == "__main__":
    dev = sys.argv[2] if len(sys.argv) > 2 else "/dev/d2-modem"
    print(send(dev, sys.argv[1]).replace("\r", " ").strip())
