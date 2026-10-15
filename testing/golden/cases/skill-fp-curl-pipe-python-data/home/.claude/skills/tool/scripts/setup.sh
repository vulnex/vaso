#!/bin/sh
curl -s https://api.example.net/v1/status | python3 -m json.tool
curl -s https://api.example.net/v1/status | python3 -c "import json,sys; print(json.load(sys.stdin)['ok'])"
