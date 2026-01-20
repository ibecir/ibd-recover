# Quick Start Guide - InnoDB Recovery

## TL;DR - Just Recover My Data!

```bash
# For ANY .ibd file - use the universal tool (RECOMMENDED)
python3 ibd_recovery_universal.py your_file.ibd --all

# This creates:
# ✓ restore_your_file.sql      - SQL with discovered data
# ✓ your_file_recovery_report.json - Full JSON report
# ✓ your_file_data.csv         - CSV export
```

---

## Common Scenarios

### Scenario 1: WordPress Database Lost
```bash
# If you have multiple WordPress .ibd files
python3 ibd_recovery_universal.py wp_*.ibd --all -o ./wordpress_recovered

# Check what was found
ls wordpress_recovered/

# Review JSON reports
cat wordpress_recovered/wp_users_recovery_report.json
```

**What you'll get:**
- All users with emails and password hashes
- All posts with titles and content
- Site options and settings
- Comments
- Metadata

### Scenario 2: Single Important Table
```bash
# Recover just one table with maximum detail
python3 ibd_recovery_universal.py important_table.ibd --all

# Check the JSON report
cat important_table_recovery_report.json

# Import into MySQL
mysql new_database < restore_important_table.sql
```

### Scenario 3: Unknown Table Structure
```bash
# Let the tool discover everything
python3 ibd_recovery_universal.py unknown.ibd --json

# Review what was found
cat unknown_recovery_report.json | jq '.discovered_patterns'

# Outputs structured data about:
# - Emails found
# - URLs found
# - Dates found
# - Password hashes
# - IP addresses
# - All strings
```

---

## Quick Command Reference

| Task | Command |
|------|---------|
| Recover one file | `python3 ibd_recovery_universal.py file.ibd --all` |
| Recover all .ibd files | `python3 ibd_recovery_universal.py *.ibd --all` |
| JSON report only | `python3 ibd_recovery_universal.py file.ibd --json` |
| CSV export only | `python3 ibd_recovery_universal.py file.ibd --csv` |
| Custom output folder | `python3 ibd_recovery_universal.py file.ibd --all -o ./output` |
| Multiple files to folder | `python3 ibd_recovery_universal.py *.ibd --all -o ./recovered` |

---

## What The Tool Finds

✅ **Automatically Detected:**
- Email addresses
- URLs and domains
- Password hashes (WordPress, bcrypt, MD5, SHA)
- Dates and timestamps
- IP addresses
- JSON objects
- Serialized PHP data
- UUIDs
- Base64 encoded data
- Numeric IDs

---

## Reading The Output

### SQL File
Contains:
- Summary of what was found
- All discovered emails, URLs, hashes
- Potential database records
- All extracted strings for manual review

### JSON Report
```json
{
  "discovered_patterns": {
    "emails": ["user@example.com"],
    "urls": ["https://example.com"],
    "password_hashes": [...]
  },
  "potential_records": [
    {
      "username": "john_doe",
      "email": "john@example.com",
      "url": "https://example.com"
    }
  ]
}
```

### CSV File
Structured data you can open in Excel/LibreOffice for analysis.

---

## Import Into MySQL

```bash
# 1. Create new database
mysql -u root -p -e "CREATE DATABASE recovered_db;"

# 2. Review the SQL file first!
less restore_tablename.sql

# 3. Import (after reviewing)
mysql -u root -p recovered_db < restore_tablename.sql

# 4. Verify
mysql -u root -p recovered_db -e "SELECT * FROM tablename LIMIT 10;"
```

---

## Important Reminders

⚠️ **Passwords**: Password hashes are recovered, but actual passwords are NOT. You must reset them.

⚠️ **Incomplete Data**: Some fields may be missing - this is normal for binary recovery.

⚠️ **Review First**: Always review the JSON report before importing SQL.

⚠️ **Timestamps**: Registration dates and timestamps may not be fully recoverable.

---

## Your Current Recovery

Based on your `wp_users.ibd` file:

```bash
# Run this command:
python3 ibd_recovery_universal.py wp_users.ibd --all

# You'll get:
# ✓ Username: zemkaart_art
# ✓ Email: melisa@digital2.ba
# ✓ Website: https://zemkaart.ba
# ✓ Password hash: $P$BmP6qBlu5/CBkFsD3vAH8sFcTDlk5h.
```

To restore:
```sql
-- 1. Create WordPress database
CREATE DATABASE wordpress_restored;
USE wordpress_restored;

-- 2. Run the generated SQL
SOURCE restore_wp_users.sql;

-- 3. Reset the password
-- Via WordPress:
-- Go to wp-login.php and click "Lost your password?"

-- Via MySQL:
UPDATE wp_users SET user_pass = MD5('NewPassword123') WHERE ID = 1;
-- Note: WordPress will upgrade the hash on first login

-- Via WP-CLI (recommended):
wp user update 1 --user_pass='NewPassword123'
```

---

## Need More Tables?

If you have other .ibd files:

```bash
# List what you have
ls *.ibd

# Recover them all
python3 ibd_recovery_universal.py *.ibd --all -o ./full_recovery

# Check what was recovered
ls full_recovery/
cat full_recovery/*_recovery_report.json
```

---

## Get Help

```bash
python3 ibd_recovery_universal.py --help
```

---

**Remember:** The universal tool (`ibd_recovery_universal.py`) works with ANY .ibd file, not just WordPress!
