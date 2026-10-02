# Blue-kit KB

Offline DFIR knowledge base and search tool.

## Usage

Build the KB:
```bash
python bk.py kb build --data /path/to/data
```

Search:
```bash
python bk.py kb search "wevtutil cl"
python bk.py kb search "vssadmin delete shadows"
```

Lookup:
```bash
python bk.py kb id T1490
```

Extract techniques from IOCs:
```bash
python bk.py kb ioc "10.0.0.5" "http://evil.com/malware.exe"
```
