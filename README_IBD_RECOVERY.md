# InnoDB .ibd File Recovery Tools

Two Python scripts for recovering data from MySQL/MariaDB InnoDB `.ibd` files when the database has been deleted.

## Scripts Overview

### 1. `ibd_recovery.py` - WordPress-Optimized Recovery
Specialized tool for recovering WordPress database tables with pre-configured schemas.

### 2. `ibd_recovery_universal.py` - Universal Recovery (RECOMMENDED)
General-purpose tool that works with **ANY** .ibd file, regardless of table structure.

---

## Universal Recovery Tool (Recommended)

### Features
- ✅ Works with ANY .ibd file (not just WordPress)
- ✅ Automatic pattern discovery (emails, URLs, dates, hashes, IPs, etc.)
- ✅ Multiple output formats: SQL, JSON, CSV
- ✅ No table schema required
- ✅ Comprehensive data extraction
- ✅ Handles password hashes (WordPress, bcrypt, MD5, SHA)
- ✅ Detects serialized data and JSON objects

### Installation

```bash
# No dependencies required - uses Python 3 standard library
chmod +x ibd_recovery_universal.py
```

### Usage

#### Basic Usage
```bash
# Recover a single file (generates SQL by default)
python3 ibd_recovery_universal.py users.ibd

# Recover with all output formats
python3 ibd_recovery_universal.py users.ibd --all

# Recover multiple files
python3 ibd_recovery_universal.py *.ibd --all
```

#### Output Formats
```bash
# Generate only JSON report
python3 ibd_recovery_universal.py data.ibd --json

# Generate only CSV
python3 ibd_recovery_universal.py data.ibd --csv

# Generate all formats (SQL + JSON + CSV)
python3 ibd_recovery_universal.py data.ibd --all

# Custom output directory
python3 ibd_recovery_universal.py data.ibd --all -o ./recovered_data
```

#### Advanced Options
```bash
# Set minimum string length (default: 3)
python3 ibd_recovery_universal.py data.ibd --min-string-length 5

# Full example
python3 ibd_recovery_universal.py wp_*.ibd --all -o ./wordpress_recovery
```

### Output Files

For each `.ibd` file processed, you get:

1. **SQL File** (`restore_<tablename>.sql`)
   - Discovered patterns summary
   - All emails, URLs, dates, hashes found
   - Potential records
   - All extracted strings for manual review

2. **JSON Report** (`<tablename>_recovery_report.json`)
   - Complete metadata
   - All discovered patterns
   - Potential database records
   - Statistics
   - All unique strings

3. **CSV File** (`<tablename>_data.csv`)
   - Structured records (if found)
   - Or all extracted strings

### Example Output

Running on `wp_users.ibd`:
```
✓ SQL file: restore_wp_users.sql
✓ JSON report: wp_users_recovery_report.json
✓ CSV file: wp_users_data.csv
✓ Emails found: 2
✓ URLs found: 1
✓ Hashes found: 1
✓ Potential records: 1
```

The JSON report contains:
```json
{
  "metadata": {
    "source_file": "wp_users.ibd",
    "file_size_bytes": 163840,
    "table_name": "wp_users",
    "total_strings_extracted": 70,
    "potential_records_found": 1
  },
  "discovered_patterns": {
    "emails": ["melisa@digital2.ba"],
    "urls": ["https://zemkaart.ba"],
    "password_hashes": [
      {
        "type": "WordPress (phpass)",
        "value": "$P$BmP6qBlu5/CBkFsD3vAH8sFcTDlk5h."
      }
    ]
  },
  "potential_records": [
    {
      "username": "zemkaart_art",
      "email": "melisa@digital2.ba",
      "url": "https://zemkaart.ba",
      "password_hash": "$P$BmP6qBlu5/CBkFsD3vAH8sFcTDlk5h."
    }
  ]
}
```

---

## WordPress-Optimized Recovery Tool

### Features
- Pre-configured WordPress table structures
- Automatic INSERT statement generation
- Supports: wp_users, wp_posts, wp_options, wp_usermeta, wp_postmeta, wp_comments

### Usage

```bash
# Recover WordPress tables
python3 ibd_recovery.py wp_users.ibd --json

# Recover multiple WordPress tables
python3 ibd_recovery.py wp_*.ibd

# Custom output directory
python3 ibd_recovery.py wp_users.ibd -o ./recovered
```

---

## What Data Can Be Recovered?

The universal tool automatically detects and extracts:

| Data Type | Examples |
|-----------|----------|
| **Emails** | user@example.com |
| **URLs** | https://example.com |
| **Password Hashes** | WordPress (phpass), bcrypt, MD5, SHA-1, SHA-256 |
| **Dates** | 2024-01-20, 01/20/2024, Unix timestamps |
| **IP Addresses** | 192.168.1.1 |
| **UUIDs** | 550e8400-e29b-41d4-a716-446655440000 |
| **JSON Objects** | {"key": "value"} |
| **Serialized PHP** | s:10:"example"; |
| **Base64 Strings** | Long base64-encoded data |
| **Numbers** | IDs, counts, etc. |

---

## How It Works

1. **String Extraction**: Uses `strings` command (or fallback Python implementation) to extract readable ASCII text from binary .ibd file

2. **Pattern Discovery**: Applies regex patterns to identify:
   - Email addresses
   - URLs
   - Dates and timestamps
   - Password hashes
   - IP addresses
   - JSON and serialized data

3. **Record Grouping**: Attempts to group related data into potential database records based on:
   - Multiple fields in single line
   - Related data proximity
   - Common patterns

4. **Output Generation**: Creates SQL, JSON, and CSV files with all discovered data

---

## Important Notes

### Password Recovery
- Password **hashes** can be recovered
- Actual **passwords** CANNOT be decrypted
- You must reset passwords after restoration

### Data Completeness
- Some fields may be incomplete due to binary file structure
- Timestamps may not be fully recoverable
- Cross-table relationships cannot be determined
- Foreign keys and constraints need manual reconstruction

### Manual Review Required
- Always review the generated files
- Verify data accuracy before importing
- Check JSON report for additional context
- Use SQL comments as guidance

---

## Restoration Workflow

### Step 1: Recover Data
```bash
python3 ibd_recovery_universal.py *.ibd --all -o ./recovered
```

### Step 2: Review JSON Reports
```bash
# Check what was found
cat recovered/*_recovery_report.json | jq '.discovered_patterns'
```

### Step 3: Create New Database
```sql
CREATE DATABASE mydb_restored;
USE mydb_restored;
```

### Step 4: Review and Execute SQL
```bash
# Review the SQL file first
less recovered/restore_users.sql

# If satisfied, import
mysql mydb_restored < recovered/restore_users.sql
```

### Step 5: Manual Cleanup
- Reset user passwords
- Verify data integrity
- Rebuild indexes if needed
- Update timestamps
- Restore relationships between tables

---

## Troubleshooting

### "strings: command not found"
The script has a built-in fallback. If you want to use the `strings` command for better performance:

**Mac:**
```bash
# strings is built-in with macOS
which strings
```

**Linux:**
```bash
sudo apt-get install binutils  # Debian/Ubuntu
sudo yum install binutils      # RHEL/CentOS
```

### No Data Recovered
- Check if .ibd file is corrupted
- Try reducing `--min-string-length` to 2
- Verify file permissions
- Check file size (should not be 0 bytes)

### Partial Data Only
- This is normal for binary recovery
- Check JSON report for all available data
- Some fields may be in separate .ibd files (like wp_usermeta)
- Cross-reference with CSV output

---

## Supported Table Types

### Universal Tool Supports
- ✅ Any MySQL/MariaDB InnoDB table
- ✅ WordPress tables
- ✅ E-commerce tables (products, orders, customers)
- ✅ User management tables
- ✅ Content management tables
- ✅ Custom application tables

### WordPress-Specific Tool Supports
- wp_users
- wp_posts
- wp_options
- wp_usermeta
- wp_postmeta
- wp_comments

---

## Examples

### Example 1: E-commerce Site Recovery
```bash
# Recover all tables
python3 ibd_recovery_universal.py shop_*.ibd --all -o ./shop_recovery

# Check what users were found
cat shop_recovery/shop_users_recovery_report.json | jq '.discovered_patterns.emails'

# Check products
cat shop_recovery/shop_products_recovery_report.json | jq '.potential_records'
```

### Example 2: WordPress Full Recovery
```bash
# Recover all WordPress tables
python3 ibd_recovery_universal.py wp_*.ibd --all -o ./wp_recovery

# Check users
cat wp_recovery/wp_users_recovery_report.json | jq '.potential_records'

# Check posts
cat wp_recovery/wp_posts_recovery_report.json | jq '.discovered_patterns'
```

### Example 3: Custom Application
```bash
# Recover custom tables
python3 ibd_recovery_universal.py app_users.ibd app_sessions.ibd app_logs.ibd --all

# Export to CSV for Excel analysis
python3 ibd_recovery_universal.py app_analytics.ibd --csv
```

---

## Performance

- **Small files** (<1 MB): ~1-2 seconds
- **Medium files** (1-10 MB): ~5-10 seconds
- **Large files** (10-100 MB): ~30-60 seconds
- **Very large files** (>100 MB): May take several minutes

---

## License

These tools are provided as-is for data recovery purposes.

---

## Support

If you encounter issues:
1. Check the JSON report for discovered data
2. Try the universal tool instead of WordPress-specific tool
3. Reduce minimum string length
4. Check file permissions and corruption

---

## Credits

Created for recovering MySQL InnoDB data files when database backups are unavailable.
