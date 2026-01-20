#!/usr/bin/env python3
"""
Universal InnoDB .ibd File Recovery Script
Recovers data from MySQL/MariaDB .ibd files and generates SQL restoration scripts
"""

import os
import re
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional


class IBDRecovery:
    """Universal InnoDB file recovery with intelligent table detection"""

    # WordPress table schemas
    WP_SCHEMAS = {
        'wp_users': {
            'sql': """CREATE TABLE IF NOT EXISTS `wp_users` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_login` varchar(60) NOT NULL DEFAULT '',
  `user_pass` varchar(255) NOT NULL DEFAULT '',
  `user_nicename` varchar(50) NOT NULL DEFAULT '',
  `user_email` varchar(100) NOT NULL DEFAULT '',
  `user_url` varchar(100) NOT NULL DEFAULT '',
  `user_registered` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `user_activation_key` varchar(255) NOT NULL DEFAULT '',
  `user_status` int(11) NOT NULL DEFAULT '0',
  `display_name` varchar(250) NOT NULL DEFAULT '',
  PRIMARY KEY (`ID`),
  KEY `user_login_key` (`user_login`),
  KEY `user_nicename` (`user_nicename`),
  KEY `user_email` (`user_email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;""",
            'fields': ['ID', 'user_login', 'user_pass', 'user_nicename', 'user_email',
                      'user_url', 'user_registered', 'user_activation_key', 'user_status', 'display_name']
        },
        'wp_usermeta': {
            'sql': """CREATE TABLE IF NOT EXISTS `wp_usermeta` (
  `umeta_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL DEFAULT '0',
  `meta_key` varchar(255) DEFAULT NULL,
  `meta_value` longtext,
  PRIMARY KEY (`umeta_id`),
  KEY `user_id` (`user_id`),
  KEY `meta_key` (`meta_key`(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;""",
            'fields': ['umeta_id', 'user_id', 'meta_key', 'meta_value']
        },
        'wp_posts': {
            'sql': """CREATE TABLE IF NOT EXISTS `wp_posts` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `post_author` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `post_date_gmt` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `post_content` longtext NOT NULL,
  `post_title` text NOT NULL,
  `post_excerpt` text NOT NULL,
  `post_status` varchar(20) NOT NULL DEFAULT 'publish',
  `comment_status` varchar(20) NOT NULL DEFAULT 'open',
  `ping_status` varchar(20) NOT NULL DEFAULT 'open',
  `post_password` varchar(255) NOT NULL DEFAULT '',
  `post_name` varchar(200) NOT NULL DEFAULT '',
  `to_ping` text NOT NULL,
  `pinged` text NOT NULL,
  `post_modified` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `post_modified_gmt` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `post_content_filtered` longtext NOT NULL,
  `post_parent` bigint(20) unsigned NOT NULL DEFAULT '0',
  `guid` varchar(255) NOT NULL DEFAULT '',
  `menu_order` int(11) NOT NULL DEFAULT '0',
  `post_type` varchar(20) NOT NULL DEFAULT 'post',
  `post_mime_type` varchar(100) NOT NULL DEFAULT '',
  `comment_count` bigint(20) NOT NULL DEFAULT '0',
  PRIMARY KEY (`ID`),
  KEY `post_name` (`post_name`(191)),
  KEY `type_status_date` (`post_type`,`post_status`,`post_date`,`ID`),
  KEY `post_parent` (`post_parent`),
  KEY `post_author` (`post_author`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;""",
            'fields': ['ID', 'post_author', 'post_date', 'post_date_gmt', 'post_content',
                      'post_title', 'post_excerpt', 'post_status']
        }
    }

    def __init__(self, ibd_file: str):
        self.ibd_file = Path(ibd_file)
        self.table_name = self.ibd_file.stem
        self.extracted_strings = []
        self.is_wordpress = self._detect_wordpress()

    def _detect_wordpress(self) -> bool:
        """Detect if this is a WordPress table"""
        return self.table_name.startswith('wp_')

    def extract_strings(self, min_length: int = 3) -> List[str]:
        """Extract readable strings from binary .ibd file"""
        try:
            result = subprocess.run(
                ['strings', '-a', '-n', str(min_length), str(self.ibd_file)],
                capture_output=True,
                text=True,
                check=True,
                timeout=60
            )
            strings = result.stdout.strip().split('\n')
        except:
            strings = self._manual_extraction(min_length)

        # Filter InnoDB markers
        self.extracted_strings = [s for s in strings
                                  if s not in ['infimum', 'supremum'] and len(s) >= min_length]
        return self.extracted_strings

    def _manual_extraction(self, min_length: int) -> List[str]:
        """Manual string extraction fallback"""
        strings = []
        current = bytearray()

        with open(self.ibd_file, 'rb') as f:
            while True:
                byte = f.read(1)
                if not byte:
                    break
                if 32 <= byte[0] <= 126:
                    current.append(byte[0])
                else:
                    if len(current) >= min_length:
                        strings.append(current.decode('ascii', errors='ignore'))
                    current = bytearray()
        return strings

    def parse_wp_users(self) -> List[Dict[str, Any]]:
        """Parse WordPress users table"""
        users = []

        # Pattern: username + $P$hash + username + email + url
        for line in self.extracted_strings:
            # Look for password hash pattern
            hash_match = re.search(r'\$P\$[A-Za-z0-9./]{31}', line)
            if not hash_match:
                continue

            user = {}
            hash_pos = hash_match.start()

            # Extract password (exactly 34 chars)
            user['user_pass'] = line[hash_pos:hash_pos + 34]

            # Extract username (before hash)
            before_hash = line[:hash_pos]
            username_match = re.search(r'([a-zA-Z0-9_-]{3,60})$', before_hash)
            if username_match:
                username = username_match.group(1)
                user['user_login'] = username
                user['user_nicename'] = username
                user['display_name'] = username

            # After hash: .username + email + url
            after_hash = line[hash_pos + 34:]

            # Skip the dot and repeated username
            if username and after_hash.startswith('.' + username):
                after_hash = after_hash[len(username) + 1:]
            elif username and after_hash.startswith(username):
                after_hash = after_hash[len(username):]

            # Extract email (clean)
            email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', after_hash)
            if email_match:
                user['user_email'] = email_match.group(1)

            # Extract URL
            url_match = re.search(r'(https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', after_hash)
            if url_match:
                user['user_url'] = url_match.group(1)

            # Set defaults
            user['ID'] = len(users) + 1
            user['user_registered'] = 'NOW()'
            user['user_activation_key'] = ''
            user['user_status'] = 0

            users.append(user)

        # Also check for standalone emails
        standalone_emails = []
        for line in self.extracted_strings:
            if '@' in line and len(line) < 100:
                email_match = re.fullmatch(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line)
                if email_match:
                    standalone_emails.append(line)

        # Merge standalone emails with existing users
        for user in users:
            for email in standalone_emails:
                if email in str(user.get('user_email', '')):
                    user['user_email'] = email
                    break

        # Deduplicate
        seen = set()
        unique_users = []
        for user in users:
            key = user.get('user_email') or user.get('user_login')
            if key and key not in seen:
                seen.add(key)
                unique_users.append(user)

        return unique_users

    def parse_generic(self) -> List[Dict[str, Any]]:
        """Parse generic table"""
        records = []

        # Discover all data
        emails = []
        urls = []
        dates = []
        hashes = []

        for line in self.extracted_strings:
            # Emails
            email_matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line)
            emails.extend(email_matches)

            # URLs
            url_matches = re.findall(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?', line)
            urls.extend(url_matches)

            # Dates
            date_matches = re.findall(r'\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?', line)
            dates.extend(date_matches)

            # Hashes
            hash_matches = re.findall(r'\$P\$[A-Za-z0-9./]{31}|\$2[ayb]\$\d{2}\$[A-Za-z0-9./]{53}', line)
            hashes.extend(hash_matches)

        # Create records from discovered data
        for email in set(emails):
            records.append({'email': email})

        return records

    def generate_sql(self, output_file: str = None) -> str:
        """Generate SQL file"""
        if not output_file:
            output_file = f"restore_{self.table_name}.sql"

        print(f"  → Extracting strings from {self.ibd_file.name}...")
        self.extract_strings()

        print(f"  → Parsing data...")

        # Parse based on table type
        if self.table_name == 'wp_users':
            records = self.parse_wp_users()
        else:
            records = self.parse_generic()

        print(f"  → Generating SQL...")

        # Build SQL
        sql = []
        sql.append("-- " + "=" * 70)
        sql.append(f"-- InnoDB Recovery: {self.table_name}")
        sql.append("-- " + "=" * 70)
        sql.append(f"-- Source file: {self.ibd_file.name}")
        sql.append(f"-- File size: {self.ibd_file.stat().st_size:,} bytes")
        sql.append(f"-- Recovery date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        sql.append(f"-- Records found: {len(records)}")
        sql.append("-- " + "=" * 70)
        sql.append("")

        # CREATE TABLE
        if self.table_name in self.WP_SCHEMAS:
            sql.append(self.WP_SCHEMAS[self.table_name]['sql'])
        else:
            # Generic table
            sql.append(f"CREATE TABLE IF NOT EXISTS `{self.table_name}` (")
            sql.append("  `id` INT AUTO_INCREMENT PRIMARY KEY,")

            # Determine columns from first record
            if records:
                for key in sorted(records[0].keys()):
                    sql.append(f"  `{key}` TEXT,")

            sql.append("  `recovered_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
            sql.append(") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;")

        sql.append("")

        # INSERT statements
        if records:
            sql.append("-- RECOVERED DATA")
            sql.append("-- " + "-" * 70)
            sql.append("")

            for i, record in enumerate(records, 1):
                if self.table_name == 'wp_users':
                    sql.append(self._build_wp_user_insert(record))
                else:
                    sql.append(self._build_generic_insert(record))
                sql.append("")
        else:
            sql.append("-- No structured records found")
            sql.append("-- Check the raw data section below")
            sql.append("")

        # Raw data for manual review
        sql.append("-- " + "=" * 70)
        sql.append("-- ALL EXTRACTED STRINGS (for manual review)")
        sql.append("-- " + "=" * 70)
        sql.append("/*")
        for s in sorted(set(self.extracted_strings))[:200]:
            sql.append(f"{s}")
        if len(set(self.extracted_strings)) > 200:
            sql.append(f"... and {len(set(self.extracted_strings)) - 200} more strings")
        sql.append("*/")
        sql.append("")

        # Footer
        sql.append("-- " + "=" * 70)
        sql.append("-- IMPORTANT:")
        sql.append("-- 1. Review all INSERT statements before executing")
        sql.append("-- 2. Password hashes recovered - actual passwords CANNOT be decrypted")
        sql.append("-- 3. Reset passwords after restoration")
        sql.append("-- 4. Some fields may be incomplete - this is normal for binary recovery")
        sql.append("-- " + "=" * 70)

        # Write file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sql))

        return output_file

    def _build_wp_user_insert(self, user: Dict[str, Any]) -> str:
        """Build WordPress user INSERT statement"""
        fields = ['ID', 'user_login', 'user_pass', 'user_nicename', 'user_email',
                 'user_url', 'user_registered', 'user_activation_key', 'user_status', 'display_name']

        values = []
        for field in fields:
            if field == 'user_registered':
                values.append('NOW()')
            elif field == 'user_activation_key':
                values.append("''")
            elif field == 'user_status':
                values.append('0')
            else:
                val = user.get(field, '')
                if val:
                    values.append(self._quote(val))
                else:
                    values.append("''")

        return f"INSERT INTO `wp_users` (`{'`, `'.join(fields)}`) VALUES ({', '.join(values)});"

    def _build_generic_insert(self, record: Dict[str, Any]) -> str:
        """Build generic INSERT statement"""
        cols = sorted(record.keys())
        col_str = '`, `'.join(cols)
        val_str = ', '.join(self._quote(record[c]) for c in cols)
        return f"INSERT INTO `{self.table_name}` (`{col_str}`) VALUES ({val_str});"

    def _quote(self, value: Any) -> str:
        """SQL quote value"""
        if value is None or value == '':
            return "''"
        if isinstance(value, int):
            return str(value)
        value = str(value).replace("'", "''").replace("\\", "\\\\")
        return f"'{value}'"


def main():
    """Main CLI"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Universal InnoDB .ibd File Recovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recover_ibd.py users.ibd
  python3 recover_ibd.py *.ibd
  python3 recover_ibd.py *.ibd -o ./recovered
        """
    )

    parser.add_argument('ibd_files', nargs='+', help='.ibd files to recover')
    parser.add_argument('-o', '--output-dir', default='.', help='Output directory')

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True, parents=True)

    print("=" * 80)
    print("Universal InnoDB .ibd File Recovery")
    print("=" * 80)
    print()

    success = 0
    total = len(args.ibd_files)

    for ibd_file in args.ibd_files:
        ibd_path = Path(ibd_file)

        if not ibd_path.exists():
            print(f"✗ File not found: {ibd_file}")
            continue

        if ibd_path.suffix != '.ibd':
            print(f"✗ Not an .ibd file: {ibd_file}")
            continue

        print(f"Processing: {ibd_file}")
        print("-" * 80)

        try:
            recovery = IBDRecovery(ibd_file)
            out_file = output_dir / f"restore_{recovery.table_name}.sql"
            recovery.generate_sql(str(out_file))
            print(f"  ✓ Generated: {out_file}")
            success += 1
            print()
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            import traceback
            traceback.print_exc()
            print()

    print("=" * 80)
    print(f"Complete: {success}/{total} files recovered")
    print("=" * 80)


if __name__ == '__main__':
    main()
