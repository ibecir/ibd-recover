# InnoDB .ibd File Recovery Tool

Universal script to recover data from MySQL/MariaDB InnoDB `.ibd` files and generate SQL restoration scripts.

## What It Does

Takes any `.ibd` file(s) and generates `.sql` file(s) that you can run on your MySQL server to restore the data.

## Requirements

- Python 3.x
- `strings` command (usually pre-installed on Mac/Linux)

## Usage

### Recover Single File

```bash
python3 recover_ibd.py your_file.ibd
```

This creates: `restore_your_file.sql`

### Recover Multiple Files

```bash
python3 recover_ibd.py file1.ibd file2.ibd file3.ibd
```

### Recover All .ibd Files in Directory

```bash
python3 recover_ibd.py *.ibd
```

### Specify Output Directory

```bash
python3 recover_ibd.py *.ibd -o ./recovered
```

## Example

```bash
# Recover WordPress users table
python3 recover_ibd.py wp_users.ibd

# Output: restore_wp_users.sql

# Import into MySQL
mysql -u root -p your_database < restore_wp_users.sql
```

## What Gets Recovered

The script automatically detects and recovers:

- ✅ Email addresses
- ✅ URLs
- ✅ Usernames
- ✅ Password hashes (WordPress, bcrypt, etc.)
- ✅ Dates and timestamps
- ✅ IP addresses
- ✅ All text data from the table

## Important Notes

1. **Password Hashes**: Passwords are recovered as hashes and cannot be decrypted. You must reset passwords after restoration.

2. **Incomplete Data**: Some fields may be incomplete due to the binary file structure. This is normal.

3. **Review First**: Always review the generated SQL file before importing it.

4. **Table Structure**: The script creates a generic table structure. You may need to adjust column types for your specific needs.

## Restoration Steps

1. **Recover the data**
   ```bash
   python3 recover_ibd.py your_file.ibd
   ```

2. **Review the SQL file**
   ```bash
   cat restore_your_file.sql
   ```

3. **Create database**
   ```bash
   mysql -u root -p -e "CREATE DATABASE recovered_db;"
   ```

4. **Import the SQL**
   ```bash
   mysql -u root -p recovered_db < restore_your_file.sql
   ```

5. **Verify the data**
   ```bash
   mysql -u root -p recovered_db -e "SELECT * FROM your_file LIMIT 10;"
   ```

## Example: WordPress Recovery

If you have WordPress `.ibd` files:

```bash
# Recover all WordPress tables
python3 recover_ibd.py wp_*.ibd -o ./wordpress_recovery

# Import into new WordPress database
mysql -u root -p wordpress < wordpress_recovery/restore_wp_users.sql
mysql -u root -p wordpress < wordpress_recovery/restore_wp_posts.sql
mysql -u root -p wordpress < wordpress_recovery/restore_wp_options.sql
# ... etc

# Reset admin password
mysql -u root -p wordpress -e "UPDATE wp_users SET user_pass = MD5('newpassword') WHERE ID = 1;"
```

## Troubleshooting

### "strings: command not found"

The script has a built-in fallback, but for best results install `strings`:

**Mac**: Already installed (part of Xcode Command Line Tools)

**Linux**:
```bash
sudo apt-get install binutils  # Debian/Ubuntu
sudo yum install binutils      # RHEL/CentOS
```

### No Data Recovered

- Check file permissions
- Verify `.ibd` file is not corrupted
- Ensure file size is greater than 0 bytes
- Try with a smaller `min_length` value (edit script if needed)

### Partial Data Only

This is normal. Binary recovery cannot guarantee 100% data recovery. Check the SQL file comments for all discovered strings.

## How It Works

1. Extracts readable ASCII strings from the binary `.ibd` file
2. Identifies patterns: emails, URLs, dates, hashes, etc.
3. Groups related data into potential database records
4. Generates SQL CREATE TABLE and INSERT statements
5. Includes all discovered data in SQL comments for manual review

## License

Free to use for data recovery purposes.

## Support

If the script doesn't work for your specific table, check the generated SQL file comments section which contains ALL extracted strings for manual review.
