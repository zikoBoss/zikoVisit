#!/usr/bin/env python3
"""
Account Simplifier - JSON Format Special
Extracts only uid and password from JSON arrays
"""

import os
import re
import sys
import json

# Colors
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    print(f"""{Colors.CYAN}{Colors.BOLD}
    ╔═══════════════════════════════════════════╗
    ║     🔥 JSON ACCOUNT EXTRACTOR 🔥          ║
    ║         (UID + Password Only)             ║
    ╚═══════════════════════════════════════════╝{Colors.END}
    """)

def print_success(msg): print(f"{Colors.GREEN}✓ {msg}{Colors.END}")
def print_error(msg): print(f"{Colors.RED}✗ {msg}{Colors.END}")
def print_warning(msg): print(f"{Colors.YELLOW}⚠ {msg}{Colors.END}")
def print_info(msg): print(f"{Colors.BLUE}ℹ {msg}{Colors.END}")
def print_cyan(msg): print(f"{Colors.CYAN}{msg}{Colors.END}")

def get_file_location():
    print_cyan("\n📁 FILE LOCATION")
    print("-" * 40)
    print("Enter JSON file path")
    print("Examples:")
    print("  • /sdcard/Download/accounts.json")
    print("  • /storage/emulated/0/accounts.txt")
    print("  • accounts.json")
    print("-" * 40)
    
    while True:
        path = input(f"{Colors.YELLOW}📂 File path: {Colors.END}").strip()
        
        if path.startswith('~'):
            path = os.path.expanduser(path)
        
        if os.path.exists(path):
            return os.path.abspath(path)
        else:
            print_error(f"File not found: {path}")
            retry = input(f"{Colors.CYAN}Try again? (y/n): {Colors.END}").lower()
            if retry != 'y':
                sys.exit(1)

def extract_from_json(content):
    accounts = []
    
    try:
        data = json.loads(content)
        
        if isinstance(data, list):
            print_info(f"Found JSON array with {len(data)} items")
            
            for i, item in enumerate(data, 1):
                try:
                    if isinstance(item, dict):
                        uid = None
                        for key in ['uid', 'UID', 'userId', 'userid', 'id', 'Id']:
                            if key in item:
                                uid = str(item[key])
                                break
                        
                        password = None
                        for key in ['password', 'pass', 'pwd', 'Password', 'Pass']:
                            if key in item:
                                password = str(item[key])
                                break
                        
                        if uid and password:
                            uid_clean = ''.join(filter(str.isdigit, str(uid)))
                            
                            if len(uid_clean) >= 5 and len(password) >= 1:
                                accounts.append({
                                    'uid': uid_clean,
                                    'password': password,
                                    'line': i
                                })
                            else:
                                print_warning(f"Item {i}: Invalid UID length or empty password")
                        else:
                            print_warning(f"Item {i}: Missing uid or password fields")
                    else:
                        print_warning(f"Item {i}: Not a valid object")
                        
                except Exception as e:
                    print_warning(f"Item {i}: Error parsing - {e}")
                    
        elif isinstance(data, dict):
            print_info("Found single JSON object")
            uid = str(data.get('uid', data.get('UID', data.get('id', ''))))
            password = str(data.get('password', data.get('pass', data.get('pwd', ''))))
            
            if uid and password:
                uid_clean = ''.join(filter(str.isdigit, uid))
                if len(uid_clean) >= 5:
                    accounts.append({
                        'uid': uid_clean,
                        'password': password,
                        'line': 1
                    })
        else:
            print_error("Unknown JSON structure")
            
    except json.JSONDecodeError as e:
        print_error(f"Invalid JSON: {e}")
        print_info("Trying line-by-line parsing...")
        lines = content.strip().split('\n')
        for i, line in enumerate(lines, 1):
            try:
                if line.strip() and line.strip().startswith('{'):
                    item = json.loads(line)
                    uid = str(item.get('uid', item.get('UID', '')))
                    password = str(item.get('password', item.get('pass', '')))
                    
                    if uid and password:
                        uid_clean = ''.join(filter(str.isdigit, uid))
                        if len(uid_clean) >= 5:
                            accounts.append({
                                'uid': uid_clean,
                                'password': password,
                                'line': i
                            })
            except:
                pass
                
    return accounts

def select_region():
    print_cyan("\n🌍 SELECT REGION")
    print("-" * 40)
    regions = {
        '1': ('BD', 'Bangladesh'),
        '2': ('IND', 'India'),
        '3': ('BR', 'Brazil'),
        '4': ('US', 'United States'),
        '5': ('ALL', 'Auto-distribute by UID')
    }
    
    for key, (code, name) in regions.items():
        print(f"  {Colors.YELLOW}{key}{Colors.END}. {code} - {name}")
    
    while True:
        choice = input(f"\n{Colors.CYAN}Select (1-5): {Colors.END}").strip()
        if choice in regions:
            return regions[choice][0]
        print_error("Invalid choice!")

def auto_detect_region(uid):
    try:
        uid_num = int(uid)
        if uid_num > 2500000000:
            return 'IND'
        elif uid_num > 1800000000:
            return 'BR'
        else:
            return 'BD'
    except:
        return 'BD'

def distribute_and_save(accounts, target_region, output_dir):
    if target_region == 'ALL':
        distributed = {'BD': [], 'IND': [], 'BR': [], 'US': []}
        for acc in accounts:
            region = auto_detect_region(acc['uid'])
            distributed[region].append(acc)
    else:
        distributed = {target_region: accounts}
    
    os.makedirs(output_dir, exist_ok=True)
    saved_files = []
    
    print_cyan("\n💾 SAVING FILES")
    print("-" * 40)
    
    for region, accs in distributed.items():
        if not accs:
            continue
            
        filename = f"accounts_{region.lower()}.txt"
        filepath = os.path.join(output_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                for acc in accs:
                    f.write(f"{acc['uid']}:{acc['password']}\n")
            
            saved_files.append({
                'region': region,
                'file': filepath,
                'count': len(accs)
            })
            print_success(f"{region}: {len(accs)} accounts → {filename}")
            
        except Exception as e:
            print_error(f"Error saving {filename}: {e}")
    
    return saved_files

def main():
    print_banner()
    
    input_file = get_file_location()
    
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        print_success(f"File loaded: {len(content)} bytes")
    except Exception as e:
        print_error(f"Cannot read file: {e}")
        return
    
    print_info("Extracting uid and password from JSON...")
    accounts = extract_from_json(content)
    
    if not accounts:
        print_error("No valid accounts found!")
        print_info("Make sure your JSON has 'uid' and 'password' fields")
        return
    
    print_success(f"Extracted {len(accounts)} valid accounts")

    # ---- NEW PART (ignore extra accounts) ----
    valid_count = (len(accounts) // 100) * 100
    ignored = len(accounts) - valid_count

    if ignored > 0:
        print_warning(f"Ignoring {ignored} extra accounts (keeping {valid_count})")
        accounts = accounts[:valid_count]
    # -----------------------------------------

    print_cyan("\n📋 SAMPLE ACCOUNTS:")
    print("-" * 40)
    
    for i, acc in enumerate(accounts[:5], 1):
        pwd = acc['password']
        if len(pwd) > 6:
            masked = pwd[:2] + '*' * (len(pwd)-4) + pwd[-2:]
        else:
            masked = '*' * len(pwd)
        print(f"  {i}. UID: {Colors.CYAN}{acc['uid']}{Colors.END} | Pass: {masked}")
    
    if len(accounts) > 5:
        print(f"  ... and {len(accounts)-5} more accounts")
    
    region = select_region()
    
    output_dir = os.path.dirname(input_file)
    
    saved = distribute_and_save(accounts, region, output_dir)
    
    print_cyan("\n📊 SUMMARY")
    print("-" * 40)
    
    total = 0
    for item in saved:
        print(f"{item['region']} → {item['count']} accounts")
        total += item['count']
    
    print_success(f"Total saved: {total}")
    print_success("Done!")

if __name__ == "__main__":
    main()