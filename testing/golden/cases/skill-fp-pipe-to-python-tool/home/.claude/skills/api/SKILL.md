---
name: api
description: query the API
---
Pretty-print a response:

```bash
curl -s https://api.example.com/v1/items | python3 -m json.tool
curl -s https://api.example.com/v1/items | python3 -c "import sys, json; print(len(json.load(sys.stdin)))"
```

Credentials are read from the macOS keychain by the official CLI; never paste them here.
