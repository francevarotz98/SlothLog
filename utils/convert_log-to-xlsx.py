import re
import os
from datetime import datetime
import pandas as pd


def parse_common_log_format(log_file_path, output_file="log_data.xlsx"):
    """
    Parse a log file in Common Log Format (CLF) or Combined Log Format and save to Excel
    CLF: %h %l %u %t \"%r\" %>s %b
    Combined: %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"
    
    Args:
        log_file_path (str): Path to the log file to parse
        output_file (str): Path to the Excel file to create
    
    Returns:
        str: Path to the created Excel file
    """
    # List to store all parsed log entries
    all_log_entries = []
    
    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                line = line.strip()
                if not line:  # Skip empty lines
                    continue
                    
                # Process each line with the original parsing logic
                # Regex pattern for standard Combined Log Format
                pattern = r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\S+) "(.*?)" "(.*?)"'
                
                # Try Combined Log Format first
                match = re.match(pattern, line)
                if match:
                    host, _, _, timestamp, request, status, bytes_str, referer, user_agent = match.groups()
                else:
                    # Try Common Log Format without referer and user-agent
                    pattern = r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\S+)'
                    match = re.match(pattern, line)
                    if match:
                        host, _, _, timestamp, request, status, bytes_str = match.groups()
                        referer, user_agent = "-", "-"
                    else:
                        # If both formats fail, try a more flexible approach
                        try:
                            print("[D] Flexible format:\n",line)
                            parts = line.split()
                            host = parts[0]
                            timestamp_str = re.search(r'\[(.*?)\]', line)
                            timestamp = timestamp_str.group(1) if timestamp_str else "-"
                            request_str = re.search(r'"(.*?)"', line)
                            request = request_str.group(1) if request_str else "-"
                            
                            # Try to extract status and bytes
                            status_match = re.search(r'" (\d+) ', line)
                            status = status_match.group(1) if status_match else "-"
                            
                            bytes_match = re.search(r'" \d+ (\S+)', line)
                            bytes_str = bytes_match.group(1) if bytes_match else "-"
                            
                            # Try to extract referer and user-agent
                            quotes = re.findall(r'"(.*?)"', line)
                            referer = quotes[1] if len(quotes) > 1 else "-"
                            user_agent = quotes[2] if len(quotes) > 2 else "-"
                        except:
                            # If parsing fails completely, skip this line
                            print("[-] Failing for:\n",line)
                            continue
                
                # Handle bytes value (could be "-" for no content)
                if bytes_str == "-":
                    bytes_val = 0
                else:
                    try:
                        bytes_val = int(bytes_str)
                    except ValueError:
                        bytes_val = 0
                
                # Try to standardize timestamp format
                try:
                    # Common format: 10/Oct/2023:13:55:36 -0700
                    dt_obj = datetime.strptime(timestamp.split()[0], "%d/%b/%Y:%H:%M:%S %z")
                    timestamp = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    # If timestamp parsing fails, keep original
                    pass
                
                # Add the parsed entry to our list
                all_log_entries.append({
                    "timestamp": timestamp,
                    "host": host,
                    "request": request,
                    "status": status,
                    "bytes": bytes_val,
                    "referer": referer,
                    "user_agent": user_agent
                })
                
    except Exception as e:
        print(f"Error reading log file: {e}")
        return None
    
    # If no valid entries were found, return None
    if not all_log_entries:
        print("[-] No valid log entries found in the file.")
        return None
    
    # Create a DataFrame with all parsed entries
    log_data_df = pd.DataFrame(all_log_entries)
    
    
    # Check if file exists, if so, append to it
    if os.path.exists(output_file):
        try:
            # Load existing data
            existing_df = pd.read_excel(output_file)
            
            # Combine existing and new data
            combined_df = pd.concat([existing_df, log_data_df], ignore_index=True)
            
            # Write combined data to Excel
            combined_df.to_excel(output_file, index=False)
            print(f"[D] Appended {len(log_data_df)} new records to existing {len(existing_df)} records in {output_file}")
            return combined_df
        except Exception as e:
            print(f"[-] Error appending to existing file: {str(e)}")
            print(f"[*] Creating new file instead")
            log_data_df.to_excel(output_file, index=False)
            return log_data_df
    else:
        # File doesn't exist, create it
        log_data_df.to_excel(output_file, index=False)
        print(f"[+] Created new file {output_file} with {len(log_data_df)} records")
        return log_data_df


OUTPUT_FILE = ".\\parsed_log.xlsx"
INPUT_FILE = input("Enter path to log file (e.g.: C:\\path\\to\\file.log): ").strip()

excel_file = parse_common_log_format(INPUT_FILE, OUTPUT_FILE)
if not excel_file.empty:
    print("[+] Excel file saved as 'parsed_log.xlsx'")
else:
    print("[-] Failed to parse log file")
