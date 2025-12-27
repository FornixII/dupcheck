# dupcheck
dupcheck is a lightweight command-line tool for identifying duplicate hostnames, IP addresses, and short-name collisions in target lists commonly used for vulnerability scanning, asset inventories, and infrastructure assessments.

The tool supports mixed input formats (hostnames, IPv4, IPv6), handles case-insensitive hostname comparisons, canonicalizes IP addresses, and detects short-name collisions (e.g., host vs host.domain.local) by default. It works with both comma-separated files and line-by-line lists, making it ideal for cleaning Nessus targets, nmap input files, CMDB exports, and manually maintained inventories.

In addition to reporting duplicates, dupcheck can generate a deduplicated output file that preserves the first-seen formatting of each entry. The output is intentionally concise and script-friendly, producing one result per line with an optional summary count for easy review or automation.

Key features:
- Case-insensitive hostname duplicate detection
- IPv4 and IPv6 duplicate detection with canonical normalization
- Short-name collision detection enabled by default
- Supports comma-separated or line-by-line input formats
- Optional comment handling (# full-line or inline)
- Generates a deduplicated output file
- Clean, Unix-style output suitable for pipelines and CI/CD
- Designed for security, ops, and infrastructure workflows

Common use cases:
- Cleaning vulnerability scanner target lists (Nessus, OpenVAS, nmap)
- Identifying redundant or conflicting asset entries
- Detecting hostname vs FQDN inconsistencies
- Normalizing mixed hostname/IP inventories
- Pre-validating scan inputs before large assessments

Example usage:
1. ./dupcheck.py hosts.txt
2. ./dupcheck.py hosts.txt -o cleaned_hosts.txt
3. ./dupcheck.py targets.txt -i -s --delimiter " "
