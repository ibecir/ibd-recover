from ibd_parser import IBDFileParser

# Initialize parser with your .ibd file
parser = IBDFileParser("wp_users.ibd")

# Analyze a specific page
page_info = parser.parse_page_directory(page_no=4)

# Access page information
print(f"Page Type: {page_info['header'].page_type}")
if 'index_header' in page_info:
    print(f"Number of records: {page_info['index_header'].n_recs}")

# Get records from an index page
records = parser.get_records(page_no=4)
for record in records:
    print(record.data)

# Hex dump of a page
parser.hex_dump(page_no=4, length=128)
