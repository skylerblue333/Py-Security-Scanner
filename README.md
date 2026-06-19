# Py-Security-Scanner

Static code analysis tool that detects hardcoded secrets, dangerous functions, and code smells.

## Quick Start

```bash
pip install -r requirements.txt
pytest tests/ -v
uvicorn src.main:app --reload
```

## API

`POST /scan` with `{"code": "password = 'hunter2'"}`  
Returns list of findings with severity, rule, and line number.
