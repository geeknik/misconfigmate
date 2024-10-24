# 🔍 MisconfigMate

MisconfigMate is a Python port and enhancement of [Intigriti's misconfig-mapper](https://github.com/intigriti/misconfig-mapper). This tool builds upon their excellent research and service templates while adding additional features and improvements.

## 🙏 Credits

This project would not be possible without the research and work done by the Intigriti team. Special thanks to:
- The [Intigriti](https://www.intigriti.com/) team for their original [misconfig-mapper](https://github.com/intigriti/misconfig-mapper) project
- Their comprehensive research on service misconfigurations
- The service template definitions that form the core of this tool
- Their commitment to open source security tooling

This Python port adds features like:
- Multi-threading support
- Enhanced progress tracking
- Additional output formats
- Improved error handling
- Extended service template support

## 🌟 Features

- **Wide Service Coverage**: Supports 30+ popular third-party services including:
  - Collaboration tools (Jira, Confluence, Notion)
  - Cloud storage (AWS S3, Google Cloud Storage, Azure Blob)
  - Development platforms (GitHub, GitLab, Bitbucket)
  - Documentation services (ReadTheDocs, GitBook)
  - Project management (Trello, Asana, Monday.com)
  - CI/CD platforms (CircleCI, Travis CI)
  - Package registries (NPM, Docker Hub)
  - And more...

- **Smart Detection**: 
  - Intelligent permutation generation for subdomain discovery
  - Pattern-based service detection
  - Misconfiguration fingerprinting
  - Rate limiting support

- **Performance**:
  - Multi-threaded scanning
  - Configurable delays and timeouts
  - Batch processing for efficient scanning
  - Progress tracking with ETA

- **Flexible Output**:
  - Interactive terminal UI with rich formatting
  - JSON/JSONL for programmatic usage
  - CSV for spreadsheet analysis
  - Webhook support for integration with other tools

## 📋 Requirements

```bash
pip install rich requests urllib3
```

Or install all requirements:
```bash
pip install -r requirements.txt
```

## 🚀 Quick Start

Basic scan of all services:
```bash
python3 misconfigmate.py -target company-name
```

Scan specific service with delay:
```bash
python3 misconfigmate.py -target company-name -service confluence -delay 1000
```

Scan with custom headers:
```bash
python3 misconfigmate.py -target company-name -headers "User-Agent: Custom;; Authorization: Bearer token"
```

## 🛠️ Usage Options

```
usage: misconfigmate.py [-h] -target TARGET [-service SERVICE] [-skip-checks] [-headers HEADERS]
                      [-delay DELAY] [-timeout TIMEOUT] [-verbose] [-output {table,json,jsonl,csv,webhook}]
                      [-webhook WEBHOOK] [-threads THREADS]

arguments:
  -target TARGET         Target domain or company name
  -service SERVICE       Service ID or name (default: all)
  -skip-checks          Only detect services without checking misconfigs
  -headers HEADERS      Custom headers ("Key: Value;; Key2: Value2")
  -delay DELAY          Delay between requests in ms (default: 0)
  -timeout TIMEOUT      Request timeout in seconds (default: 10)
  -verbose              Show detailed output
  -output FORMAT        Output format (table/json/jsonl/csv/webhook)
  -webhook URL          Webhook URL for sending results
  -threads THREADS      Number of concurrent threads (default: 5)
```

## 📊 Example Output

```
Scanning target: company-name [▓▓▓▓▓▓▓▓▓░] 45% • Endpoints: 23/50 • 00:21 • Discovered: 3

Scan Results:
┌─────────────┬────────────────────────────┬────────────┬───────────────────────┐
│ Service     │ URL                        │ Status     │ Description           │
├─────────────┼────────────────────────────┼────────────┼───────────────────────┤
│ Confluence  │ https://company.atlassian...│ VULNERABLE │ Public space access...│
│ AWS S3      │ https://company.s3.amazon...│ EXISTS     │ Bucket listing enab...│
└─────────────┴────────────────────────────┴────────────┴───────────────────────┘

Found 2 unique results.
Total discovered endpoints: 3
```

## ⚡ Service Templates

Service detection and vulnerability checks are defined in `templates/services.json`. Each service has:
- Detection fingerprints for service identification
- Vulnerability fingerprints for misconfiguration detection 
- Request specifications (method, path, headers)
- Expected response patterns
- Documentation and remediation steps

The template format follows Intigriti's original structure with some enhancements:
```json
{
    "id": "1",
    "request": {
        "method": "GET",
        "baseURL": "https://{TARGET}.example.com",
        "path": ["/api/check"],
        "headers": {},
        "body": null
    },
    "response": {
        "statusCode": [200, 404],
        "detectionFingerprints": ["service-identifier"],
        "fingerprints": ["misconfiguration-pattern"]
    },
    "metadata": {
        "service": "example",
        "serviceName": "Example Service",
        "description": "Service description",
        "reproductionSteps": [],
        "references": []
    }
}
```

## 🔒 Security Notes

- Use responsibly and only scan targets you have permission to test
- Consider rate limiting with `-delay` to avoid overwhelming services
- Some services may log or block aggressive scanning
- Review results carefully to avoid false positives
- Follow responsible disclosure practices when reporting issues

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional service templates
- Better fingerprint patterns
- False positive reduction
- Performance optimizations
- Documentation improvements

Please ensure your PRs maintain compatibility with the original misconfig-mapper templates.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details. The original service templates and research are credited to Intigriti's misconfig-mapper project.

## ⚠️ Disclaimer

MisconfigMate is a Python port of Intigriti's misconfig-mapper, designed for security professionals to assess their own organizations' security posture. Users are responsible for ensuring they have permission to scan their targets. The authors are not responsible for misuse or for any damage that may result from using this tool.

## 🔗 Links

- [Original misconfig-mapper](https://github.com/intigriti/misconfig-mapper)
- [Intigriti Blog](https://blog.intigriti.com/)
- [Service Documentation](https://bugology.intigriti.io/misconfig-mapper-docs/)
