#!/usr/bin/env python3
"""
Universal InnoDB .ibd File Recovery Tool
Extracts data from ANY MySQL/MariaDB InnoDB .ibd file and generates restoration scripts

This tool works with ANY .ibd file, not just WordPress tables.
"""

import os
import re
import sys
import json
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict


class UniversalIBDRecovery:
    """Universal InnoDB file recovery - works with any table"""

    def __init__(self, ibd_file: str, table_schema: Optional[Dict] = None):
        self.ibd_file = Path(ibd_file)
        self.table_name = self._extract_table_name()
        self.extracted_strings = []
        self.table_schema = table_schema
        self.discovered_data = {
            'emails': [],
            'urls': [],
            'dates': [],
            'numbers': [],
            'ip_addresses': [],
            'hashes': [],
            'json_objects': [],
            'serialized_data': [],
            'all_strings': []
        }

    def _extract_table_name(self) -> str:
        """Extract table name from filename"""
        return self.ibd_file.stem

    def extract_strings(self, min_length: int = 3) -> List[str]:
        """Extract readable strings from binary .ibd file"""
        try:
            result = subprocess.run(
                ['strings', '-a', '-n', str(min_length), str(self.ibd_file)],
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            self.extracted_strings = result.stdout.strip().split('\n')
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            self.extracted_strings = self._manual_string_extraction(min_length)

        # Filter out InnoDB markers
        self.extracted_strings = [s for s in self.extracted_strings
                                  if s not in ['infimum', 'supremum'] and len(s) >= min_length]

        return self.extracted_strings

    def _manual_string_extraction(self, min_length: int = 3) -> List[str]:
        """Manually extract strings if 'strings' command unavailable"""
        strings = []
        current_string = bytearray()

        with open(self.ibd_file, 'rb') as f:
            while True:
                byte = f.read(1)
                if not byte:
                    break

                if 32 <= byte[0] <= 126:  # Printable ASCII
                    current_string.append(byte[0])
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string.decode('ascii', errors='ignore'))
                    current_string = bytearray()

        return strings

    def discover_patterns(self) -> Dict[str, List]:
        """Discover all common data patterns in the extracted strings"""

        patterns = {
            'emails': re.compile(r'\b[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
            'urls': re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?'),
            'ip_addresses': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'dates_iso': re.compile(r'\b\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?\b'),
            'dates_us': re.compile(r'\b\d{1,2}/\d{1,2}/\d{2,4}\b'),
            'timestamps': re.compile(r'\b\d{10,13}\b'),  # Unix timestamps
            'md5_hashes': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha_hashes': re.compile(r'\b[a-fA-F0-9]{40,64}\b'),
            'wordpress_hashes': re.compile(r'\$P\$[A-Za-z0-9./]{31}'),
            'bcrypt_hashes': re.compile(r'\$2[ayb]\$\d{2}\$[A-Za-z0-9./]{53}'),
            'uuids': re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'),
            'json_objects': re.compile(r'\{["\w].*?:["\w].*?\}'),
            'serialized_php': re.compile(r'[aOs]:\d+:\{.*?\}'),
            'base64': re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b'),
        }

        for line in self.extracted_strings:
            # Store all strings
            self.discovered_data['all_strings'].append(line)

            # Match specific patterns
            for email in patterns['emails'].findall(line):
                if email not in self.discovered_data['emails']:
                    self.discovered_data['emails'].append(email)

            for url in patterns['urls'].findall(line):
                if url not in self.discovered_data['urls']:
                    self.discovered_data['urls'].append(url)

            for ip in patterns['ip_addresses'].findall(line):
                if ip not in self.discovered_data['ip_addresses']:
                    self.discovered_data['ip_addresses'].append(ip)

            # Dates
            for date in patterns['dates_iso'].findall(line):
                if date not in self.discovered_data['dates']:
                    self.discovered_data['dates'].append(date)
            for date in patterns['dates_us'].findall(line):
                if date not in self.discovered_data['dates']:
                    self.discovered_data['dates'].append(date)

            # Hashes
            hash_found = False
            for wp_hash in patterns['wordpress_hashes'].findall(line):
                self.discovered_data['hashes'].append({'type': 'WordPress (phpass)', 'value': wp_hash})
                hash_found = True
            for bcrypt in patterns['bcrypt_hashes'].findall(line):
                self.discovered_data['hashes'].append({'type': 'bcrypt', 'value': bcrypt})
                hash_found = True
            if not hash_found:
                for md5 in patterns['md5_hashes'].findall(line):
                    self.discovered_data['hashes'].append({'type': 'MD5', 'value': md5})
                for sha in patterns['sha_hashes'].findall(line):
                    hash_type = 'SHA-256' if len(sha) == 64 else 'SHA-1'
                    self.discovered_data['hashes'].append({'type': hash_type, 'value': sha})

            # JSON
            for json_obj in patterns['json_objects'].findall(line):
                try:
                    parsed = json.loads(json_obj)
                    self.discovered_data['json_objects'].append(json_obj)
                except:
                    pass

            # Serialized PHP
            for ser in patterns['serialized_php'].findall(line):
                if ser not in self.discovered_data['serialized_data']:
                    self.discovered_data['serialized_data'].append(ser)

            # Numbers (generic integers that might be IDs)
            if line.isdigit() and 1 <= len(line) <= 10:
                self.discovered_data['numbers'].append(int(line))

        # Deduplicate hashes
        seen_hashes = set()
        unique_hashes = []
        for hash_item in self.discovered_data['hashes']:
            hash_val = hash_item['value']
            if hash_val not in seen_hashes:
                seen_hashes.add(hash_val)
                unique_hashes.append(hash_item)
        self.discovered_data['hashes'] = unique_hashes

        return self.discovered_data

    def group_related_data(self) -> List[Dict[str, Any]]:
        """
        Attempt to group related data into potential records
        Returns list of potential database records
        """
        records = []

        # Strategy 1: Find lines with multiple data types (likely a full record)
        for line in self.extracted_strings:
            record = {}
            has_multiple_fields = False
            field_count = 0

            # Check for email
            email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line)
            if email_match:
                record['email'] = email_match.group()
                field_count += 1

            # Check for URL
            url_match = re.search(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line)
            if url_match:
                record['url'] = url_match.group()
                field_count += 1

            # Check for hash
            hash_match = re.search(r'\$P\$[A-Za-z0-9./]{31}|\$2[ayb]\$\d{2}\$[A-Za-z0-9./]{53}', line)
            if hash_match:
                record['password_hash'] = hash_match.group()
                field_count += 1

            # Check for username patterns (alphanumeric with underscores)
            if hash_match:
                before_hash = line[:line.find(hash_match.group())]
                username_match = re.search(r'([a-zA-Z0-9_-]{3,60})$', before_hash)
                if username_match:
                    record['username'] = username_match.group(1)
                    field_count += 1

            # If we found multiple fields in one line, it's likely a record
            if field_count >= 2:
                record['_raw_line'] = line
                record['_field_count'] = field_count
                records.append(record)

        # Strategy 2: Standalone fields (for simpler tables)
        if not records:
            for line in self.extracted_strings:
                if '@' in line and len(line) < 100:  # Likely just an email
                    email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line)
                    if email_match and email_match.group() == line:
                        records.append({'email': line, '_raw_line': line})

        return records

    def generate_sql(self, output_file: Optional[str] = None) -> str:
        """Generate SQL file with recovered data"""
        if output_file is None:
            output_file = f"restore_{self.table_name}.sql"

        # Extract and discover
        self.extract_strings()
        self.discover_patterns()
        records = self.group_related_data()

        # Build SQL content
        sql_lines = []
        sql_lines.append("-- " + "=" * 70)
        sql_lines.append(f"-- Universal InnoDB Recovery: {self.table_name}")
        sql_lines.append("-- " + "=" * 70)
        sql_lines.append(f"-- Source file: {self.ibd_file.name}")
        sql_lines.append(f"-- Recovery date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        sql_lines.append(f"-- Total strings extracted: {len(self.extracted_strings)}")
        sql_lines.append(f"-- Potential records found: {len(records)}")
        sql_lines.append("-- " + "=" * 70)
        sql_lines.append("")

        # Add CREATE TABLE if schema provided
        if self.table_schema and 'create_sql' in self.table_schema:
            sql_lines.append(self.table_schema['create_sql'])
            sql_lines.append("")

        # Data summary
        sql_lines.append("-- DISCOVERED DATA SUMMARY")
        sql_lines.append("-- " + "-" * 70)
        sql_lines.append(f"-- Emails found: {len(self.discovered_data['emails'])}")
        sql_lines.append(f"-- URLs found: {len(self.discovered_data['urls'])}")
        sql_lines.append(f"-- Dates found: {len(self.discovered_data['dates'])}")
        sql_lines.append(f"-- Password hashes found: {len(self.discovered_data['hashes'])}")
        sql_lines.append(f"-- IP addresses found: {len(self.discovered_data['ip_addresses'])}")
        sql_lines.append("-- " + "-" * 70)
        sql_lines.append("")

        # Show discovered data
        if self.discovered_data['emails']:
            sql_lines.append("-- EMAILS:")
            for email in self.discovered_data['emails']:
                sql_lines.append(f"--   {email}")
            sql_lines.append("")

        if self.discovered_data['urls']:
            sql_lines.append("-- URLS:")
            for url in self.discovered_data['urls']:
                sql_lines.append(f"--   {url}")
            sql_lines.append("")

        if self.discovered_data['hashes']:
            sql_lines.append("-- PASSWORD HASHES:")
            for hash_item in self.discovered_data['hashes']:
                sql_lines.append(f"--   [{hash_item['type']}] {hash_item['value']}")
            sql_lines.append("")

        if self.discovered_data['dates']:
            sql_lines.append("-- DATES:")
            for date in self.discovered_data['dates'][:20]:  # Limit to first 20
                sql_lines.append(f"--   {date}")
            sql_lines.append("")

        # Potential records
        if records:
            sql_lines.append("-- POTENTIAL RECORDS:")
            sql_lines.append("-- Use these to manually construct INSERT statements")
            sql_lines.append("/*")
            for i, record in enumerate(records, 1):
                sql_lines.append(f"-- Record #{i}:")
                for key, value in record.items():
                    if not key.startswith('_'):
                        sql_lines.append(f"--   {key}: {value}")
                sql_lines.append(f"--   Raw: {record.get('_raw_line', 'N/A')}")
                sql_lines.append("--")
            sql_lines.append("*/")
            sql_lines.append("")

        # All unique strings (for manual parsing)
        sql_lines.append("-- ALL EXTRACTED STRINGS (for manual review):")
        sql_lines.append("/*")
        unique_strings = sorted(set(self.extracted_strings))
        for s in unique_strings[:200]:  # Limit to first 200
            sql_lines.append(f"-- {s}")
        if len(unique_strings) > 200:
            sql_lines.append(f"-- ... and {len(unique_strings) - 200} more strings")
        sql_lines.append("*/")
        sql_lines.append("")

        # Footer
        sql_lines.append("-- " + "=" * 70)
        sql_lines.append("-- NOTES:")
        sql_lines.append("-- This is an automated recovery. Manual review required.")
        sql_lines.append("-- Check the JSON report for structured data.")
        sql_lines.append("-- Use discovered patterns to reconstruct INSERT statements.")
        sql_lines.append("-- " + "=" * 70)

        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sql_lines))

        return output_file

    def generate_json_report(self, output_file: Optional[str] = None) -> str:
        """Generate comprehensive JSON report"""
        if output_file is None:
            output_file = f"{self.table_name}_recovery_report.json"

        records = self.group_related_data()

        report = {
            "metadata": {
                "source_file": str(self.ibd_file),
                "file_size_bytes": self.ibd_file.stat().st_size,
                "table_name": self.table_name,
                "recovery_timestamp": datetime.now().isoformat(),
                "total_strings_extracted": len(self.extracted_strings),
                "potential_records_found": len(records)
            },
            "discovered_patterns": {
                "emails": self.discovered_data['emails'],
                "urls": self.discovered_data['urls'],
                "dates": self.discovered_data['dates'],
                "password_hashes": self.discovered_data['hashes'],
                "ip_addresses": self.discovered_data['ip_addresses'],
                "json_objects": self.discovered_data['json_objects'],
                "serialized_data": self.discovered_data['serialized_data']
            },
            "potential_records": records,
            "all_unique_strings": sorted(set(self.extracted_strings)),
            "statistics": {
                "total_unique_strings": len(set(self.extracted_strings)),
                "emails_found": len(self.discovered_data['emails']),
                "urls_found": len(self.discovered_data['urls']),
                "hashes_found": len(self.discovered_data['hashes']),
                "dates_found": len(self.discovered_data['dates'])
            }
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return output_file

    def generate_csv(self, output_file: Optional[str] = None) -> str:
        """Generate CSV file with discovered data"""
        if output_file is None:
            output_file = f"{self.table_name}_data.csv"

        records = self.group_related_data()

        if not records:
            # If no structured records, output all strings
            import csv
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['extracted_string'])
                for s in sorted(set(self.extracted_strings)):
                    writer.writerow([s])
        else:
            # Output structured records
            import csv
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                # Get all possible fields
                all_fields = set()
                for record in records:
                    all_fields.update(k for k in record.keys() if not k.startswith('_'))
                all_fields = sorted(all_fields)

                writer = csv.DictWriter(f, fieldnames=all_fields, extrasaction='ignore')
                writer.writeheader()
                for record in records:
                    clean_record = {k: v for k, v in record.items() if not k.startswith('_')}
                    writer.writerow(clean_record)

        return output_file


def main():
    """CLI interface"""
    parser = argparse.ArgumentParser(
        description='Universal InnoDB .ibd File Recovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Recover single file with all output formats
  python ibd_recovery_universal.py data.ibd --all

  # Recover multiple files, JSON only
  python ibd_recovery_universal.py *.ibd --json

  # Recover with custom output directory
  python ibd_recovery_universal.py users.ibd -o ./recovered

  # Recover to CSV format
  python ibd_recovery_universal.py transactions.ibd --csv
        """
    )

    parser.add_argument('ibd_files', nargs='+', help='.ibd files to recover')
    parser.add_argument('--sql', action='store_true', help='Generate SQL file (default)')
    parser.add_argument('--json', action='store_true', help='Generate JSON report')
    parser.add_argument('--csv', action='store_true', help='Generate CSV file')
    parser.add_argument('--all', action='store_true', help='Generate all output formats')
    parser.add_argument('--output-dir', '-o', help='Output directory', default='.')
    parser.add_argument('--min-string-length', type=int, default=3,
                       help='Minimum string length to extract (default: 3)')

    args = parser.parse_args()

    # If no format specified, default to SQL
    if not (args.sql or args.json or args.csv or args.all):
        args.sql = True

    if args.all:
        args.sql = args.json = args.csv = True

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True, parents=True)

    print("=" * 80)
    print("Universal InnoDB .ibd File Recovery Tool")
    print("=" * 80)
    print()

    for ibd_file in args.ibd_files:
        ibd_path = Path(ibd_file)

        if not ibd_path.exists():
            print(f"ERROR: File not found: {ibd_file}")
            continue

        if ibd_path.suffix != '.ibd':
            print(f"WARNING: {ibd_file} is not an .ibd file, skipping...")
            continue

        print(f"Processing: {ibd_file}")
        print("-" * 80)

        try:
            recovery = UniversalIBDRecovery(ibd_file)

            # Extract strings first
            print(f"  Extracting strings (min length: {args.min_string_length})...")
            recovery.extract_strings(min_length=args.min_string_length)
            print(f"  ✓ Extracted {len(recovery.extracted_strings)} strings")

            # Discover patterns
            print(f"  Discovering data patterns...")
            recovery.discover_patterns()

            # Generate outputs
            if args.sql:
                sql_file = output_dir / f"restore_{recovery.table_name}.sql"
                recovery.generate_sql(str(sql_file))
                print(f"  ✓ SQL file: {sql_file}")

            if args.json:
                json_file = output_dir / f"{recovery.table_name}_recovery_report.json"
                recovery.generate_json_report(str(json_file))
                print(f"  ✓ JSON report: {json_file}")

            if args.csv:
                csv_file = output_dir / f"{recovery.table_name}_data.csv"
                recovery.generate_csv(str(csv_file))
                print(f"  ✓ CSV file: {csv_file}")

            # Show summary
            print(f"  ✓ Emails found: {len(recovery.discovered_data['emails'])}")
            print(f"  ✓ URLs found: {len(recovery.discovered_data['urls'])}")
            print(f"  ✓ Hashes found: {len(recovery.discovered_data['hashes'])}")
            print(f"  ✓ Potential records: {len(recovery.group_related_data())}")
            print()

        except Exception as e:
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()
            print()

    print("=" * 80)
    print("Recovery complete! Review the generated files for recovered data.")
    print("=" * 80)


if __name__ == '__main__':
    main()
