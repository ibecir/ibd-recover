#!/usr/bin/env python3
"""
InnoDB .ibd File Recovery Tool
Extracts data from MySQL InnoDB .ibd files and generates SQL restoration scripts
"""

import os
import re
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional


class IBDRecovery:
    """Main class for recovering data from .ibd files"""

    # WordPress table structures
    WP_TABLE_STRUCTURES = {
        'wp_users': {
            'create_sql': """
CREATE TABLE IF NOT EXISTS `wp_users` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_login` varchar(60) NOT NULL DEFAULT '',
  `user_pass` varchar(255) NOT NULL DEFAULT '',
  `user_nicename` varchar(50) NOT NULL DEFAULT '',
  `user_email` varchar(100) NOT NULL DEFAULT '',
  `user_url` varchar(100) NOT NULL DEFAULT '',
  `user_registered` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `user_activation_key` varchar(255) NOT NULL DEFAULT '',
  `user_status` int(11) NOT NULL DEFAULT '0',
  `display_name` varchar(250) NOT NULL DEFAULT '',
  PRIMARY KEY (`ID`),
  KEY `user_login_key` (`user_login`),
  KEY `user_nicename` (`user_nicename`),
  KEY `user_email` (`user_email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
""",
            'fields': ['ID', 'user_login', 'user_pass', 'user_nicename', 'user_email',
                      'user_url', 'user_registered', 'user_activation_key', 'user_status', 'display_name']
        },
        'wp_posts': {
            'create_sql': """
CREATE TABLE IF NOT EXISTS `wp_posts` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `post_author` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_date` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `post_date_gmt` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
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
  `post_modified` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `post_modified_gmt` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
""",
            'fields': ['ID', 'post_author', 'post_date', 'post_date_gmt', 'post_content',
                      'post_title', 'post_excerpt', 'post_status', 'comment_status',
                      'ping_status', 'post_password', 'post_name', 'to_ping', 'pinged',
                      'post_modified', 'post_modified_gmt', 'post_content_filtered',
                      'post_parent', 'guid', 'menu_order', 'post_type', 'post_mime_type', 'comment_count']
        },
        'wp_options': {
            'create_sql': """
CREATE TABLE IF NOT EXISTS `wp_options` (
  `option_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `option_name` varchar(191) NOT NULL DEFAULT '',
  `option_value` longtext NOT NULL,
  `autoload` varchar(20) NOT NULL DEFAULT 'yes',
  PRIMARY KEY (`option_id`),
  UNIQUE KEY `option_name` (`option_name`),
  KEY `autoload` (`autoload`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
""",
            'fields': ['option_id', 'option_name', 'option_value', 'autoload']
        },
        'wp_usermeta': {
            'create_sql': """
CREATE TABLE IF NOT EXISTS `wp_usermeta` (
  `umeta_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL DEFAULT '0',
  `meta_key` varchar(255) DEFAULT NULL,
  `meta_value` longtext,
  PRIMARY KEY (`umeta_id`),
  KEY `user_id` (`user_id`),
  KEY `meta_key` (`meta_key`(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
""",
            'fields': ['umeta_id', 'user_id', 'meta_key', 'meta_value']
        },
        'wp_postmeta': {
            'create_sql': """
CREATE TABLE IF NOT EXISTS `wp_postmeta` (
  `meta_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `post_id` bigint(20) unsigned NOT NULL DEFAULT '0',
  `meta_key` varchar(255) DEFAULT NULL,
  `meta_value` longtext,
  PRIMARY KEY (`meta_id`),
  KEY `post_id` (`post_id`),
  KEY `meta_key` (`meta_key`(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
""",
            'fields': ['meta_id', 'post_id', 'meta_key', 'meta_value']
        },
        'wp_comments': {
            'create_sql': """
CREATE TABLE IF NOT EXISTS `wp_comments` (
  `comment_ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `comment_post_ID` bigint(20) unsigned NOT NULL DEFAULT '0',
  `comment_author` tinytext NOT NULL,
  `comment_author_email` varchar(100) NOT NULL DEFAULT '',
  `comment_author_url` varchar(200) NOT NULL DEFAULT '',
  `comment_author_IP` varchar(100) NOT NULL DEFAULT '',
  `comment_date` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `comment_date_gmt` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `comment_content` text NOT NULL,
  `comment_karma` int(11) NOT NULL DEFAULT '0',
  `comment_approved` varchar(20) NOT NULL DEFAULT '1',
  `comment_agent` varchar(255) NOT NULL DEFAULT '',
  `comment_type` varchar(20) NOT NULL DEFAULT 'comment',
  `comment_parent` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_id` bigint(20) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`comment_ID`),
  KEY `comment_post_ID` (`comment_post_ID`),
  KEY `comment_approved_date_gmt` (`comment_approved`,`comment_date_gmt`),
  KEY `comment_date_gmt` (`comment_date_gmt`),
  KEY `comment_parent` (`comment_parent`),
  KEY `comment_author_email` (`comment_author_email`(10))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
""",
            'fields': ['comment_ID', 'comment_post_ID', 'comment_author', 'comment_author_email',
                      'comment_author_url', 'comment_author_IP', 'comment_date', 'comment_date_gmt',
                      'comment_content', 'comment_karma', 'comment_approved', 'comment_agent',
                      'comment_type', 'comment_parent', 'user_id']
        }
    }

    def __init__(self, ibd_file: str):
        self.ibd_file = Path(ibd_file)
        self.table_name = self._extract_table_name()
        self.extracted_strings = []
        self.recovered_data = []

    def _extract_table_name(self) -> str:
        """Extract table name from filename"""
        filename = self.ibd_file.stem
        return filename

    def extract_strings(self, min_length: int = 3) -> List[str]:
        """Extract readable strings from binary .ibd file"""
        try:
            # Use strings command if available
            result = subprocess.run(
                ['strings', '-a', '-n', str(min_length), str(self.ibd_file)],
                capture_output=True,
                text=True,
                check=True
            )
            self.extracted_strings = result.stdout.strip().split('\n')
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback: manual string extraction
            self.extracted_strings = self._manual_string_extraction(min_length)

        return self.extracted_strings

    def _manual_string_extraction(self, min_length: int = 3) -> List[str]:
        """Manually extract strings from binary file if 'strings' command is unavailable"""
        strings = []
        current_string = bytearray()

        with open(self.ibd_file, 'rb') as f:
            while True:
                byte = f.read(1)
                if not byte:
                    break

                # Check if byte is printable ASCII
                if 32 <= byte[0] <= 126:
                    current_string.append(byte[0])
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string.decode('ascii', errors='ignore'))
                    current_string = bytearray()

        return strings

    def parse_wp_users(self) -> List[Dict[str, Any]]:
        """Parse wp_users table data"""
        users = []

        # Filter out InnoDB markers
        data_strings = [s for s in self.extracted_strings
                       if s not in ['infimum', 'supremum'] and len(s) > 2]

        # Look for email pattern to identify user records
        email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
        url_pattern = re.compile(r'https?://[\w\.-]+\.\w+')
        password_pattern = re.compile(r'\$P\$[A-Za-z0-9./]+')

        for line in data_strings:
            # Check if line contains email
            email_match = email_pattern.search(line)
            password_match = password_pattern.search(line)
            url_match = url_pattern.search(line)

            if email_match or password_match:
                # Try to extract user data from this line
                user_data = self._parse_user_line(line, email_match, password_match, url_match)
                if user_data:
                    users.append(user_data)

        # Also check for standalone emails and usernames
        emails = [s for s in data_strings if email_pattern.fullmatch(s)]
        usernames = [s for s in data_strings if len(s) > 3 and '_' in s and '@' not in s]

        # Deduplicate and merge user records
        users = self._merge_duplicate_users(users)

        # If we found separate components but no merged users, try to reconstruct user
        if emails and not users:
            for email in emails:
                user_data = {
                    'ID': 1,
                    'user_login': 'unknown',
                    'user_email': email,
                    'user_pass': '',
                    'user_url': '',
                    'display_name': 'unknown'
                }
                users.append(user_data)

        return users

    def _merge_duplicate_users(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge duplicate user records based on email or username"""
        merged = {}

        for user in users:
            # Use email or username as key
            key = user.get('user_email') or user.get('user_login') or 'unknown'

            if key in merged:
                # Merge with existing record - prefer non-empty values
                for field, value in user.items():
                    if value and (not merged[key].get(field) or len(str(value)) > len(str(merged[key].get(field, '')))):
                        merged[key][field] = value
            else:
                merged[key] = user

        return list(merged.values())

    def _parse_user_line(self, line: str, email_match, password_match, url_match) -> Optional[Dict[str, Any]]:
        """Parse a single line that might contain user data"""
        user_data = {
            'ID': 1,  # Default, actual ID hard to recover
            'user_login': '',
            'user_pass': '',
            'user_nicename': '',
            'user_email': '',
            'user_url': '',
            'display_name': ''
        }

        # Parse password hash first (most reliable marker)
        if password_match:
            # WordPress phpass hashes are exactly 34 characters: $P$ + 31 chars
            password_start = password_match.start()
            user_data['user_pass'] = line[password_start:password_start + 34]

            # Look for username immediately before the hash
            before_pass = line[:password_start]
            username_match = re.search(r'([a-zA-Z0-9_-]{3,60})$', before_pass)
            if username_match:
                username = username_match.group(1)
                user_data['user_login'] = username
                user_data['user_nicename'] = username
                user_data['display_name'] = username

            # After the password hash, there might be username again, then email
            # Pattern: username + $P$hash. + username + email + url
            after_pass = line[password_start + 34:]

            # Skip repeated username if present
            # If username was found, try to skip it in after_pass
            if user_data['user_login']:
                # Look for username repetition after the password
                username = user_data['user_login']
                # The pattern might be: username + email (with or without leading dot/separator)
                # Try with dot first, then without
                if after_pass.startswith(f".{username}"):
                    after_pass = after_pass[len(username) + 1:]
                elif after_pass.startswith(username):
                    after_pass = after_pass[len(username):]

            # First, try to extract URL (more specific pattern)
            url_in_after = re.search(r'https?://[\w\.-]+\.\w+', after_pass)
            if url_in_after:
                user_data['user_url'] = url_in_after.group()

            # Extract email - should be at the start now after skipping username
            email_in_after = re.search(r'^([a-zA-Z0-9\.-]+@[a-zA-Z0-9\.-]+\.[a-z]+)', after_pass)
            if email_in_after:
                user_data['user_email'] = email_in_after.group(1)
            else:
                # Fallback: search anywhere
                email_in_after = re.search(r'([a-zA-Z0-9\.-]+@[a-zA-Z0-9\.-]+\.[a-z]+)', after_pass)
                if email_in_after:
                    user_data['user_email'] = email_in_after.group(1)

        # If no password but has email or URL, still parse
        if not password_match:
            if email_match:
                user_data['user_email'] = email_match.group()
            if url_match:
                user_data['user_url'] = url_match.group()

        # Check if we have at least email or username
        if user_data['user_email'] or user_data['user_login']:
            return user_data

        return None

    def parse_wp_posts(self) -> List[Dict[str, Any]]:
        """Parse wp_posts table data"""
        posts = []
        # This is more complex - would need to identify post patterns
        # For now, return basic structure
        return posts

    def parse_wp_options(self) -> List[Dict[str, Any]]:
        """Parse wp_options table data"""
        options = []

        # Look for common WordPress option patterns
        for line in self.extracted_strings:
            if any(opt in line for opt in ['siteurl', 'home', 'blogname', 'admin_email']):
                options.append({
                    'option_name': line,
                    'option_value': '',
                    'autoload': 'yes'
                })

        return options

    def parse_generic(self) -> List[str]:
        """Parse generic table - return all meaningful strings"""
        return [s for s in self.extracted_strings
                if s not in ['infimum', 'supremum'] and len(s) > 3]

    def generate_sql(self, output_file: Optional[str] = None) -> str:
        """Generate SQL restoration script"""
        if output_file is None:
            output_file = f"restore_{self.table_name}.sql"

        # Extract strings first
        self.extract_strings()

        # Parse based on table type
        if self.table_name == 'wp_users':
            self.recovered_data = self.parse_wp_users()
        elif self.table_name == 'wp_posts':
            self.recovered_data = self.parse_wp_posts()
        elif self.table_name == 'wp_options':
            self.recovered_data = self.parse_wp_options()
        else:
            self.recovered_data = self.parse_generic()

        # Generate SQL
        sql_content = self._build_sql()

        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(sql_content)

        return output_file

    def _build_sql(self) -> str:
        """Build SQL content"""
        lines = []
        lines.append("-- " + "=" * 70)
        lines.append(f"-- WordPress {self.table_name} Table Recovery SQL")
        lines.append("-- " + "=" * 70)
        lines.append(f"-- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"-- Source: {self.ibd_file.name}")
        lines.append("-- " + "=" * 70)
        lines.append("")

        # Add CREATE TABLE if we know the structure
        if self.table_name in self.WP_TABLE_STRUCTURES:
            lines.append(self.WP_TABLE_STRUCTURES[self.table_name]['create_sql'])
            lines.append("")

        # Add INSERT statements
        if self.table_name == 'wp_users' and self.recovered_data:
            lines.append("-- Recovered user data")
            for user in self.recovered_data:
                insert = self._build_user_insert(user)
                lines.append(insert)
                lines.append("")
        elif self.table_name == 'wp_options' and self.recovered_data:
            lines.append("-- Recovered options data")
            for option in self.recovered_data:
                insert = self._build_option_insert(option)
                lines.append(insert)
                lines.append("")
        else:
            # Generic data dump as comments
            lines.append("-- Recovered strings from table:")
            lines.append("-- Note: Manual parsing required for this table type")
            lines.append("/*")
            for item in self.recovered_data[:100]:  # Limit to first 100 items
                lines.append(f"-- {item}")
            lines.append("*/")

        # Add notes
        lines.append("")
        lines.append("-- " + "=" * 70)
        lines.append("-- RECOVERY NOTES:")
        lines.append("-- " + "=" * 70)
        lines.append(f"-- Total records recovered: {len(self.recovered_data)}")
        lines.append("-- Some data may be incomplete due to binary file structure")
        lines.append("-- Timestamps may need to be updated manually")
        lines.append("-- Passwords hashes are recovered but passwords cannot be decrypted")
        lines.append("-- " + "=" * 70)

        return '\n'.join(lines)

    def _build_user_insert(self, user: Dict[str, Any]) -> str:
        """Build INSERT statement for wp_users"""
        return f"""INSERT INTO `wp_users` (
  `ID`,
  `user_login`,
  `user_pass`,
  `user_nicename`,
  `user_email`,
  `user_url`,
  `user_registered`,
  `user_activation_key`,
  `user_status`,
  `display_name`
) VALUES (
  {user.get('ID', 1)},
  {self._quote(user.get('user_login', ''))},
  {self._quote(user.get('user_pass', ''))},
  {self._quote(user.get('user_nicename', user.get('user_login', '')))},
  {self._quote(user.get('user_email', ''))},
  {self._quote(user.get('user_url', ''))},
  NOW(),
  '',
  {user.get('user_status', 0)},
  {self._quote(user.get('display_name', user.get('user_login', '')))}
);"""

    def _build_option_insert(self, option: Dict[str, Any]) -> str:
        """Build INSERT statement for wp_options"""
        return f"""INSERT INTO `wp_options` (`option_name`, `option_value`, `autoload`)
VALUES ({self._quote(option.get('option_name', ''))},
        {self._quote(option.get('option_value', ''))},
        {self._quote(option.get('autoload', 'yes'))});"""

    def _quote(self, value: str) -> str:
        """Quote and escape SQL string value"""
        if value is None or value == '':
            return "''"
        # Escape single quotes
        value = str(value).replace("'", "''").replace("\\", "\\\\")
        return f"'{value}'"

    def generate_json_report(self, output_file: Optional[str] = None) -> str:
        """Generate JSON report of recovered data"""
        if output_file is None:
            output_file = f"{self.table_name}_recovered_data.json"

        report = {
            "recovery_info": {
                "source_file": str(self.ibd_file),
                "table_name": self.table_name,
                "recovery_date": datetime.now().isoformat(),
                "total_records": len(self.recovered_data)
            },
            "recovered_data": self.recovered_data
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return output_file


def main():
    """Main CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(
        description='InnoDB .ibd File Recovery Tool - Extract data and generate SQL',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Recover single file
  python ibd_recovery.py wp_users.ibd

  # Recover multiple files
  python ibd_recovery.py wp_users.ibd wp_posts.ibd wp_options.ibd

  # Recover all .ibd files in current directory
  python ibd_recovery.py *.ibd

  # Generate JSON report
  python ibd_recovery.py wp_users.ibd --json
        """
    )

    parser.add_argument('ibd_files', nargs='+', help='.ibd files to recover')
    parser.add_argument('--json', action='store_true', help='Also generate JSON report')
    parser.add_argument('--output-dir', '-o', help='Output directory for generated files', default='.')

    args = parser.parse_args()

    # Create output directory if needed
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    print("=" * 70)
    print("InnoDB .ibd File Recovery Tool")
    print("=" * 70)
    print()

    for ibd_file in args.ibd_files:
        ibd_path = Path(ibd_file)

        if not ibd_path.exists():
            print(f"ERROR: File not found: {ibd_file}")
            continue

        if not ibd_path.suffix == '.ibd':
            print(f"WARNING: {ibd_file} is not an .ibd file, skipping...")
            continue

        print(f"Processing: {ibd_file}")
        print("-" * 70)

        try:
            recovery = IBDRecovery(ibd_file)

            # Generate SQL
            sql_file = output_dir / f"restore_{recovery.table_name}.sql"
            recovery.generate_sql(str(sql_file))
            print(f"  ✓ SQL file generated: {sql_file}")

            # Generate JSON if requested
            if args.json:
                json_file = output_dir / f"{recovery.table_name}_recovered_data.json"
                recovery.generate_json_report(str(json_file))
                print(f"  ✓ JSON report generated: {json_file}")

            print(f"  ✓ Records recovered: {len(recovery.recovered_data)}")
            print()

        except Exception as e:
            print(f"  ERROR: Failed to process {ibd_file}: {e}")
            import traceback
            traceback.print_exc()
            print()

    print("=" * 70)
    print("Recovery complete!")
    print("=" * 70)


if __name__ == '__main__':
    main()
