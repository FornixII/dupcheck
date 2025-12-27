#!/usr/bin/env python3
VERSION = "1.0.0"

import argparse
import ipaddress
import re
from collections import defaultdict
from typing import Dict, List, Tuple


# Strict IPv4 dotted-quad (prevents "10" from being treated as an IP)
_IPV4_RE = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
)


def strip_inline_comment(s: str, comment_char: str = "#") -> str:
    idx = s.find(comment_char)
    return s[:idx].rstrip() if idx != -1 else s


def parse_hosts_from_line(line: str, delimiter: str) -> List[str]:
    parts = [p.strip() for p in line.split(delimiter)]
    return [p for p in parts if p]  # drop empties (e.g., trailing comma)


def read_items(
    path: str,
    ignore_comments: bool,
    strip_inline: bool,
    comment_char: str,
    delimiter: str,
) -> List[str]:
    """
    Reads tokens from a file.
    Supports comma-separated lists and/or one token per line.
    """
    items: List[str] = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue

            if ignore_comments and s.startswith(comment_char):
                continue

            if ignore_comments and strip_inline:
                s = strip_inline_comment(s, comment_char=comment_char).strip()
                if not s:
                    continue

            items.extend(parse_hosts_from_line(s, delimiter=delimiter))

    return items


def is_ipv4(token: str) -> bool:
    return bool(_IPV4_RE.fullmatch(token))


def is_ipv6(token: str) -> bool:
    if ":" not in token:
        return False
    try:
        ipaddress.IPv6Address(token)
        return True
    except ValueError:
        return False


def is_ip(token: str) -> bool:
    return is_ipv4(token) or is_ipv6(token)


def normalize_ip(token: str) -> str:
    """
    Canonicalize IP formatting (IPv6 compressed, etc.).
    Assumes token is a valid IPv4 dotted-quad or IPv6.
    """
    return str(ipaddress.ip_address(token))


def short_name(host: str) -> str:
    return host.split(".", 1)[0]


def find_hostname_duplicates(items: List[str]) -> Dict[str, int]:
    """
    Case-insensitive hostname duplicate detection.
    Only includes duplicates (count > 1).
    Excludes IP addresses.
    """
    counts: Dict[str, int] = defaultdict(int)
    for raw in items:
        if is_ip(raw):
            continue
        counts[raw.lower()] += 1
    return {k: v for k, v in counts.items() if v > 1}


def find_ip_duplicates(items: List[str]) -> Dict[str, int]:
    """
    IP duplicate detection (IPv4 + IPv6), canonicalized.
    Only includes duplicates (count > 1).
    """
    counts: Dict[str, int] = defaultdict(int)
    for raw in items:
        if not is_ip(raw):
            continue
        counts[normalize_ip(raw)] += 1
    return {k: v for k, v in counts.items() if v > 1}


def find_shortname_collisions(items: List[str]) -> Dict[str, int]:
    """
    Short-name collisions for hostnames only (excludes IPs).
    Returns: shortname(lower) -> number_of_distinct_full_hosts_colliding
    """
    buckets: Dict[str, set] = defaultdict(set)
    for raw in items:
        if is_ip(raw):
            continue
        sn = short_name(raw).lower()
        buckets[sn].add(raw.lower())

    collisions: Dict[str, int] = {}
    for sn, fulls in buckets.items():
        if len(fulls) > 1:
            collisions[sn] = len(fulls)
    return collisions


def write_deduplicated_output(items: List[str], output_path: str, delimiter: str) -> None:
    """
    Writes a deduplicated list:
    - Hostnames deduped case-insensitively (keeps first original casing)
    - IPs deduped by canonical form (keeps first-seen original string)
    Output is delimiter-separated.
    """
    seen_hosts = set()
    seen_ips = set()
    out: List[str] = []

    for raw in items:
        if is_ip(raw):
            key = normalize_ip(raw)
            if key in seen_ips:
                continue
            seen_ips.add(key)
            out.append(raw)
        else:
            key = raw.lower()
            if key in seen_hosts:
                continue
            seen_hosts.add(key)
            out.append(raw)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"{delimiter} ".join(out))
        f.write("\n")


def main():
    p = argparse.ArgumentParser(
        prog="dupcheck",
        description="Detect hostname duplicates (case-insensitive), IP duplicates, and short-name collisions (default).",
        epilog="""
Examples:
  dupcheck hosts.txt
  dupcheck hosts.txt -i -s
  dupcheck hosts.txt -o cleaned_hosts.txt
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("file", help="Path to input file.")
    p.add_argument("-d", "--delimiter", default=",", help="Delimiter between items (default: ',').")

    p.add_argument("-i", "--ignore-comments", action="store_true",
                   help="Ignore full-line comments (starting with #).")
    p.add_argument("-s", "--strip-inline-comments", action="store_true",
                   help="Strip inline comments after the comment character (use with -i).")
    p.add_argument("--comment-char", default="#", help="Comment character (default: #).")

    p.add_argument("-o", "--dedupe-output",
                   help="Write a deduplicated list to this file (keeps first occurrence).")

    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {VERSION}")

    p.add_argument("--exit-nonzero", action="store_true",
                   help="Exit with code 2 if duplicates/collisions are found.")

    args = p.parse_args()

    items = read_items(
        args.file,
        ignore_comments=args.ignore_comments,
        strip_inline=args.strip_inline_comments,
        comment_char=args.comment_char,
        delimiter=args.delimiter,
    )

    host_dupes = find_hostname_duplicates(items)
    ip_dupes = find_ip_duplicates(items)
    collisions = find_shortname_collisions(items)

    any_findings = False
    total_occurrences = 0

    # One line per finding, no blank lines
    for host in sorted(host_dupes.keys()):
        any_findings = True
        count = host_dupes[host]
        total_occurrences += count
        print(f"{host} -> {host_dupes[host]} occurrences")

    for ip in sorted(ip_dupes.keys()):
        any_findings = True
        count = ip_dupes[ip]
        total_occurrences += count
        print(f"{ip} -> {ip_dupes[ip]} occurrences")

    for sn in sorted(collisions.keys()):
        any_findings = True
        print(f"{sn} -> {collisions[sn]} collisions")

    if args.dedupe_output:
        write_deduplicated_output(items, args.dedupe_output, args.delimiter)
        print(f"Deduplicated output written to: {args.dedupe_output}")

    if total_occurrences:
        print(f"TOTAL duplicate occurrences: {total_occurrences}")
        
    if args.exit_nonzero and any_findings:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
