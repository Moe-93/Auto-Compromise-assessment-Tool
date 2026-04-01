# CAT Tool v2.0 - Master Index

## Quick Navigation

### Getting Started
- **[README.md](README.md)** - Main documentation and overview
- **[QUICKSTART.md](QUICKSTART.md)** - Quick start guide
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Command reference card

### Collection
- **[COLLECTION_GUIDE.md](COLLECTION_GUIDE.md)** - Detailed collection documentation
- **[Collect-WindowsArtifacts.ps1](Collect-WindowsArtifacts.ps1)** - Windows PowerShell collector
- **[collect_linux_artifacts.sh](collect_linux_artifacts.sh)** - Linux Bash collector

### Usage Examples
- **[EXAMPLES.py](EXAMPLES.py)** - 20 detailed usage scenarios

### Technical Documentation
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Architecture overview
- **[PROJECT_SUMMARY.txt](PROJECT_SUMMARY.txt)** - Complete project summary

## Usage Patterns

### Pattern 1: Integrated Collection + Analysis (Recommended)
```bash
# Windows
python cat.py --collect --os windows --analyze

# Linux
sudo python cat.py --collect --os linux --analyze
```

### Pattern 2: Standalone Collection
```powershell
# Windows
.\Collect-WindowsArtifacts.ps1 -Package

# Linux
sudo ./collect_linux_artifacts.sh -p
```

### Pattern 3: Analyze Existing Artifacts
```bash
python cat.py --collected-dir ./artifacts/hostname_timestamp
```

### Pattern 4: Single File Analysis
```bash
python cat.py --single-file /var/log/auth.log --artifact-type sshlogin
```

## File Structure

```
ca_tool/
├── cat.py                              # Main application
├── Collect-WindowsArtifacts.ps1        # Windows standalone collector
├── collect_linux_artifacts.sh          # Linux standalone collector
├── demo.py                             # Demo script
├── EXAMPLES.py                         # Usage examples
├── README.md                           # Main documentation
├── QUICKSTART.md                       # Quick start
├── QUICK_REFERENCE.md                  # Reference card
├── COLLECTION_GUIDE.md                 # Collection guide
├── IMPLEMENTATION_SUMMARY.md           # Architecture
├── PROJECT_SUMMARY.txt                 # Project summary
├── Master_Index.md                     # This file
├── requirements.txt                    # Dependencies
│
├── collectors/
│   ├── __init__.py
│   └── artifact_collector.py           # Collection engine
│
├── config/
│   ├── __init__.py
│   └── mitre_config.py                 # MITRE mappings
│
├── parsers/
│   ├── __init__.py
│   ├── windows_parser.py               # Windows parser
│   └── linux_parser.py                 # Linux parser
│
├── mitre_mapping/
│   ├── __init__.py
│   └── mitre_mapper.py                 # ATT&CK mapper
│
├── reports/
│   ├── __init__.py
│   └── report_generator.py             # Report generator
│
└── utils/
    ├── __init__.py
    └── test_data_generator.py          # Test data
```

## Support Matrix

| Feature | Windows | Linux |
|---------|---------|-------|
| Integrated Collection | ✓ | ✓ |
| Standalone Collection | ✓ (PowerShell) | ✓ (Bash) |
| Artifact Parsing | ✓ | ✓ |
| MITRE Mapping | ✓ | ✓ |
| HTML Reports | ✓ | ✓ |
| JSON Reports | ✓ | ✓ |
| Packaging | ✓ (ZIP) | ✓ (tar.gz) |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - No critical findings |
| 1 | High severity findings detected |
| 2 | Critical findings detected |
| 130 | Interrupted by user |

## Need Help?

1. Check [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for common commands
2. See [COLLECTION_GUIDE.md](COLLECTION_GUIDE.md) for collection details
3. Review [EXAMPLES.py](EXAMPLES.py) for usage scenarios
4. Run `python cat.py --list-artifacts` to see supported artifacts
5. Check `collection.log` in the collection directory for errors

## License & Usage

⚠️ **For authorized forensic investigations only.**

This tool is designed for security professionals conducting authorized compromise assessments and incident response. Always ensure proper authorization before collecting or analyzing systems.

---

**Version**: 2.0  
**Last Updated**: 2024  
**Status**: Production Ready
