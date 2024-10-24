# Changelog

## v0.1.0 (2024-10-24)

### Feat

- **helm**: Further improvements and customizing, basic functionality added
- **helm**: Initial version of 'fluent-bit-syslog-to-aws-cloudtrail-data'
- Dockerfile to build fluent-bit image including aws-cloudtrail-data plugin
- CloudTrail Data 'PutAuditEvents' implemented
- Read CloudTrail Channel Arn from param or env var
- AWS SDK go v2 added, AWS Config and STS GetCallerIdentity implemented
- **logging**: logrus introduced, print and 'log.*' statements replaced
- Generate CloudTrail Lake event schema from event records
- Basic message parsing functionality
- go mod init and fluent bit output plugin boilerplate

### Fix

- **Dockerfile**: labels added, refactoring, fluent-bit pinned to 3.1.9
- License header in'.pre-commit-config.yaml' set to 'CC0-1.0'

### Refactor

- Minor changes, cleanup, comments added
- unused code dropped, functions and structs moved into separate files
