import re
import argparse
import datetime

def generate_sql_from_pvefw_log(input_file, output_file, table_name):
    """
    Parses Proxmox Firewall (PVEFW) logs and generates SQL CREATE and INSERT statements.
    """
    # Regex to capture the fixed initial fields and the key-value pairs at the end
    # This is the core logic for parsing each line
    log_pattern = re.compile(
        r"(?P<pvefw_chain>\S+)\s"
        r"(?P<log_timestamp>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s-\d{4})\s"
        r"(?P<action>\w+):\s"
        r"(?P<kv_pairs>.*)"
    )

    # List of all possible columns we might find in the logs
    all_columns = [
        'pvefw_chain', 'log_timestamp', 'action', 'IN', 'PHYSIN', 'PHYSOUT', 'MAC',
        'SRC', 'DST', 'LEN', 'TOS', 'PREC', 'TTL', 'ID', 'PROTO', 'SPT', 'DPT',
        'WINDOW', 'RES', 'SYN', 'URGP', 'ACK', 'PSH', 'RST', 'FIN', 'TYPE', 'CODE'
    ]
    
    # Let's define reasonable SQL types for these columns
    column_types = {
        'id': 'INT AUTO_INCREMENT PRIMARY KEY',
        'pvefw_chain': 'VARCHAR(50)',
        'log_timestamp': 'DATETIME',
        'action': 'VARCHAR(20)',
        'IN': 'VARCHAR(20)',
        'PHYSIN': 'VARCHAR(20)',
        'PHYSOUT': 'VARCHAR(20)',
        'MAC': 'VARCHAR(50)',
        'SRC': 'VARCHAR(45)',
        'DST': 'VARCHAR(45)',
        'LEN': 'INT',
        'TOS': 'VARCHAR(10)',
        'PREC': 'VARCHAR(10)',
        'TTL': 'INT',
        'ID': 'INT',
        'PROTO': 'VARCHAR(10)',
        'SPT': 'INT',
        'DPT': 'INT',
        'WINDOW': 'INT',
        'RES': 'VARCHAR(10)',
        'SYN': 'BOOLEAN',
        'URGP': 'INT',
        'ACK': 'BOOLEAN',
        'PSH': 'BOOLEAN',
        'RST': 'BOOLEAN',
        'FIN': 'BOOLEAN',
        'TYPE': 'INT',
        'CODE': 'INT'
    }

    try:
        with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
            print(f"Reading from '{input_file}' and writing to '{output_file}'...")

            # --- Generate CREATE TABLE statement ---
            f_out.write(f"-- Auto-generated CREATE TABLE statement for PVE Firewall logs\n")
            f_out.write(f"CREATE TABLE IF NOT EXISTS {table_name} (\n")
            f_out.write(f"    id {column_types['id']},\n")
            
            # Define columns that are always present first
            fixed_columns = ['pvefw_chain', 'log_timestamp', 'action']
            for col in fixed_columns:
                f_out.write(f"    {col.lower()} {column_types[col]},\n")
            
            # Define the rest of the potential columns
            for col in all_columns:
                if col not in fixed_columns:
                    f_out.write(f"    {col.lower()} {column_types.get(col, 'VARCHAR(255)')},\n")
            
            f_out.write("    raw_log TEXT\n") # Store the original line for reference
            f_out.write(");\n\n")
            f_out.write("-- DML to insert data\n")

            # --- Generate INSERT statements ---
            for line in f_in:
                # Some lines might have leading garbage, we strip it
                clean_line = line.strip().split('PVEFW-HOST-IN', 1)[-1]
                clean_line = 'PVEFW-HOST-IN' + clean_line
                
                match = log_pattern.match(clean_line)
                if not match:
                    print(f"Warning: Skipping malformed line: {line.strip()}")
                    continue

                data = match.groupdict()
                kv_pairs_str = data.pop('kv_pairs')
                
                # Parse the key-value string
                try:
                    kv_pairs = dict(pair.split('=', 1) for pair in kv_pairs_str.split())
                    data.update(kv_pairs)
                except ValueError:
                    print(f"Warning: Could not parse key-value pairs in line: {line.strip()}")
                    continue

                # --- Data Cleaning and Formatting ---
                # Convert timestamp to SQL DATETIME format
                try:
                    dt_obj = datetime.datetime.strptime(data['log_timestamp'], '%d/%b/%Y:%H:%M:%S %z')
                    data['log_timestamp'] = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    data['log_timestamp'] = None # Handle potential parsing errors
                
                # Handle boolean flags like SYN, ACK, etc.
                for flag in ['SYN', 'ACK', 'PSH', 'RST', 'FIN']:
                    if flag in data:
                        data[flag] = '1' # Represent as TRUE

                # Prepare for SQL INSERT
                columns_to_insert = ['raw_log']
                values_to_insert = [line.strip().replace("'", "''")] # Store raw log

                for col, val in data.items():
                    columns_to_insert.append(col.lower())
                    # Sanitize for SQL by escaping single quotes
                    sanitized_val = str(val).replace("'", "''")
                    values_to_insert.append(sanitized_val)
                
                columns_sql = ", ".join(columns_to_insert)
                values_sql = "', '".join(values_to_insert)

                insert_sql = f"INSERT INTO {table_name} ({columns_sql}) VALUES ('{values_sql}');\n"
                f_out.write(insert_sql)

            print("Successfully generated SQL file.")

    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Proxmox Firewall logs to SQL.")
    parser.add_argument("input_file", help="The path to the input log file.")
    parser.add_argument("output_file", help="The path for the generated SQL output file.")
    parser.add_argument("--table", default="pve_firewall_logs", help="The name of the database table (default: pve_firewall_logs).")
    
    args = parser.parse_args()
    
    generate_sql_from_pvefw_log(args.input_file, args.output_file, args.table)
