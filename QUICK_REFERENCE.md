# CAT Tool Quick Reference Card

## One-Liners

### Windows
```powershell
# Collect & analyze
python cat.py --collect --os windows --analyze

# Collect specific artifacts
python cat.py --collect --os windows --artifacts SecurityWELS PowerShellOperationalWELS

# Collect & package
python cat.py --collect --os windows --package
```

### Linux
```bash
# Collect & analyze (root)
sudo python cat.py --collect --os linux --analyze

# Collect specific artifacts
sudo python cat.py --collect --os linux --artifacts ShellHistory SSHLogin

# Collect & package
sudo python cat.py --collect --os linux --package
```

## Common Workflows

### Incident Response
```bash
# 1. Collect evidence
python cat.py --collect --os <windows|linux> --package

# 2. Analyze
python cat.py --collected-dir ./artifacts/hostname_timestamp

# 3. Review report
firefox reports/compromise_assessment_report_*.html
```

### Triage
```bash
# Quick collection & analysis
python cat.py --collect --os linux --analyze --artifacts SSHLogin SecureEvents

# Check exit code
echo $?  # 0=OK, 1=High, 2=Critical
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | No critical findings | Routine review |
| 1 | High severity findings | Investigation required |
| 2 | Critical findings | Immediate escalation |
| 130 | Interrupted | Re-run collection |

## Artifact Categories

### Windows Priority Artifacts
1. SecurityWELS (Event ID 4624, 4625, 4672, 4720, 7045)
2. PowerShellOperationalWELS
3. Prefetch
4. Autoruns
5. RunningProcesses

### Linux Priority Artifacts
1. SSHLogin (/var/log/auth.log)
2. ShellHistory (.bash_history)
3. SecureEvents
4. Crontab
5. Systemd

## File Locations

### Collection Output
```
collected_artifacts/
└── hostname_YYYYMMDD_HHMMSS/
    ├── Windows/ or Linux/
    ├── collection.log
    └── *_collection_summary.json
```

### Analysis Output
```
reports/
├── compromise_assessment_report_YYYYMMDD_HHMMSS.html
└── compromise_assessment_report_YYYYMMDD_HHMMSS.json
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Access denied (Windows) | Run as Administrator |
| Permission denied (Linux) | Use sudo |
| File locked | Normal - check collection.log |
| Command not found | Install missing packages |
| Large output | Use --artifacts to limit scope |

## Need Help?

1. Check COLLECTION_GUIDE.md for detailed info
2. Review EXAMPLES.py for scenarios
3. See README.md for general usage
4. Check collection.log for errors
