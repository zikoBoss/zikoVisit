from flask import Flask, jsonify, request
import aiohttp
import asyncio
import json
import threading
import time
import os
import sys
import logging
import traceback
from datetime import datetime
from byte import encrypt_api, Encrypt_ID
from visit_count_pb2 import Info

# ==================== LOGGING SETUP ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ==================== CONFIGURATION ====================
TOKENS_PER_REQUEST = 20
BATCH_SIZE = 20
MAX_CONCURRENT_REQUESTS = 50
REQUEST_TIMEOUT = 10
TOKEN_REFRESH_INTERVAL = 2 * 60 * 60  # 2 hours

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = SCRIPT_DIR
API_BASE_URL = "https://jwt-gen-vaibhav.vercel.app/token"

# Region configurations
REGIONS = {
    'IND': {'accounts': 'accounts_ind.txt', 'tokens': 'token_ind.json'},
    'BD':  {'accounts': 'accounts_bd.txt',  'tokens': 'token_bd.json'},
    'BR':  {'accounts': 'accounts_br.txt',  'tokens': 'token_br.json'},
    'US':  {'accounts': 'accounts_us.txt',  'tokens': 'token_us.json'},
    'NA':  {'accounts': 'accounts_na.txt',  'tokens': 'token_br.json'},  # NA uses BR
    'SAC': {'accounts': 'accounts_sac.txt', 'tokens': 'token_br.json'},  # SAC uses BR
}

# Global state
token_rotation = {}
last_token_refresh = {}
refresh_lock = threading.Lock()
is_refreshing = False

# ==================== FILE HELPERS ====================
def get_file_path(filename):
    return os.path.join(SCRIPT_DIR, filename)

def load_accounts_for_region(region):
    """Load accounts for specific region"""
    region = region.upper()
    if region not in REGIONS:
        logger.error(f"Unknown region: {region}")
        return []
    
    filepath = get_file_path(REGIONS[region]['accounts'])
    
    try:
        if not os.path.exists(filepath):
            logger.warning(f"Accounts file not found: {filepath}")
            return []
        
        accounts = []
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Support multiple separators: : ; | = space tab
                uid, password = None, None
                
                for sep in [':', ';', '|', '=', '\t']:
                    if sep in line:
                        parts = line.split(sep, 1)
                        if len(parts) == 2:
                            uid = parts[0].strip()
                            password = parts[1].strip()
                            break
                
                # Try space if no separator found
                if not uid and ' ' in line:
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        uid, password = parts[0].strip(), parts[1].strip()
                
                if uid and password:
                    # Validate UID (digits only, min 5 chars)
                    uid_clean = ''.join(filter(str.isdigit, uid))
                    if len(uid_clean) >= 5:
                        accounts.append({
                            "uid": uid_clean,
                            "password": password,
                            "line_num": line_num,
                            "region": region
                        })
                    else:
                        logger.warning(f"Invalid UID at line {line_num}: {uid}")
                else:
                    logger.warning(f"Could not parse line {line_num}: {line[:30]}...")
        
        logger.info(f"Loaded {len(accounts)} accounts for {region} from {filepath}")
        return accounts
        
    except Exception as e:
        logger.error(f"Error loading accounts for {region}: {e}")
        return []

# ==================== TOKEN REFRESH ====================
async def fetch_single_token(session, account):
    """Fetch JWT token using Vaibhav's API with full error handling"""
    uid = account["uid"]
    password = account["password"]
    region = account.get("region", "BD")

    print(f"✅ TOKEN REFRESHING FOR UID: {uid}", flush=True)
    logger.info(f"[TOKEN] Refreshing token for UID: {uid}")

    try:
        url = f"{API_BASE_URL}?uid={uid}&password={password}"

        async with session.get(
            url, 
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            ssl=False
        ) as resp:

            if resp.status == 200:
                try:
                    data = await resp.json()
                except Exception as e:
                    print(f"❌ JSON ERROR FOR UID: {uid} - {e}", flush=True)
                    return {
                        "success": False,
                        "error": "Invalid JSON response",
                        "uid": uid,
                        "region": region
                    }

                # Check for "live" status (Vaibhav's API format)
                if data.get("status") == "live":
                    jwt_token = data.get("token", "")
                    resp_region = data.get("region", region)
                    account_uid = str(data.get("uid", uid))

                    if jwt_token and len(jwt_token) > 50:
                        print(f"✅ TOKEN REFRESHED FOR UID: {uid} | Region: {resp_region} | Length: {len(jwt_token)}", flush=True)
                        logger.info(f"[TOKEN] Success for {uid}")
                        return {
                            "success": True,
                            "uid": account_uid,
                            "token": jwt_token,
                            "region": resp_region.upper()
                        }
                    else:
                        print(f"❌ TOKEN TOO SHORT FOR UID: {uid} | Length: {len(jwt_token)}", flush=True)
                        return {
                            "success": False,
                            "error": "Empty or invalid token",
                            "uid": uid,
                            "region": region
                        }
                else:
                    error_msg = data.get("message", data.get("status", "Unknown error"))
                    print(f"❌ API ERROR FOR UID: {uid} - {error_msg}", flush=True)
                    return {
                        "success": False,
                        "error": error_msg,
                        "uid": uid,
                        "region": region
                    }
            else:
                print(f"❌ HTTP ERROR FOR UID: {uid} - Status {resp.status}", flush=True)
                return {
                    "success": False,
                    "error": f"HTTP {resp.status}",
                    "uid": uid,
                    "region": region
                }

    except asyncio.TimeoutError:
        print(f"❌ TIMEOUT FOR UID: {uid}", flush=True)
        return {
            "success": False,
            "error": "Timeout",
            "uid": uid,
            "region": region
        }
    except Exception as e:
        print(f"❌ EXCEPTION FOR UID: {uid} - {e}", flush=True)
        return {
            "success": False,
            "error": str(e),
            "uid": uid,
            "region": region
        }

async def refresh_region_tokens(region):
    """Refresh tokens for a specific region"""
    region = region.upper()
    accounts = load_accounts_for_region(region)
    
    if not accounts:
        logger.warning(f"No accounts found for {region}")
        return False
    
    print(f"\n{'='*60}", flush=True)
    print(f"🔄 STARTING TOKEN REFRESH FOR REGION: {region}", flush=True)
    print(f"🔄 Total Accounts: {len(accounts)}", flush=True)
    print(f"{'='*60}\n", flush=True)

    logger.info(f"[{region}] Refreshing {len(accounts)} accounts...")
    start_time = time.time()
    
    all_tokens = []
    success_count = 0
    fail_count = 0
    
    connector = aiohttp.TCPConnector(
        limit=MAX_CONCURRENT_REQUESTS,
        limit_per_host=30,
        ttl_dns_cache=300,
        use_dns_cache=True,
    )
    
    timeout = aiohttp.ClientTimeout(total=60)
    
    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        ) as session:
            
            # Process in batches
            for i in range(0, len(accounts), BATCH_SIZE):
                batch = accounts[i:i + BATCH_SIZE]
                
                tasks = [
                    asyncio.create_task(fetch_single_token(session, acc))
                    for acc in batch
                ]
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Exception in batch: {result}")
                        fail_count += 1
                        continue
                    
                    if result.get("success"):
                        all_tokens.append({
                            "uid": result["uid"],
                            "token": result["token"],
                            "region": result["region"]
                        })
                        success_count += 1
                    else:
                        fail_count += 1
                        logger.warning(f"Failed {result.get('uid')}: {result.get('error')}")
                
                # Progress log
                if (i // BATCH_SIZE + 1) % 5 == 0:
                    logger.info(f"Progress: {i+len(batch)}/{len(accounts)} processed")
                
                # Delay between batches
                if i + BATCH_SIZE < len(accounts):
                    await asyncio.sleep(0.2)
        
        # Save tokens
        token_file = get_file_path(REGIONS[region]['tokens'])
        try:
            with open(token_file, "w") as f:
                json.dump(all_tokens, f, indent=2)
            
            # Update rotation
            token_rotation[region] = {
                'all_tokens': [t["token"] for t in all_tokens],
                'current_index': 0,
                'total_tokens': len(all_tokens)
            }
            
            elapsed = time.time() - start_time
            print(f"\n{'='*60}", flush=True)
            print(f"✅ TOKENS SAVED {len(all_tokens)} FOR {region}", flush=True)
            print(f"✅ Success: {success_count} | Failed: {fail_count} | Time: {elapsed:.1f}s", flush=True)
            print(f"{'='*60}\n", flush=True)

            logger.info(f"[{region}] Saved {len(all_tokens)} tokens in {elapsed:.1f}s")
            
            last_token_refresh[region] = time.time()
            return True
            
        except Exception as e:
            logger.error(f"❌ Error saving tokens for {region}: {e}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Critical error refreshing {region}: {e}")
        logger.error(traceback.format_exc())
        return False

def refresh_all_tokens_sync():
    """Refresh all regions (thread-safe)"""
    global is_refreshing

    with refresh_lock:
        if is_refreshing:
            logger.warning("Refresh already in progress")
            return
        is_refreshing = True

    try:
        logger.info("="*60)
        logger.info("STARTING TOKEN REFRESH FOR ALL REGIONS")
        logger.info("="*60)

        for region in REGIONS.keys():
            # Get or create event loop properly
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
            except RuntimeError:
                # No event loop in current thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            try:
                success = loop.run_until_complete(refresh_region_tokens(region))
                if not success:
                    logger.warning(f"Failed to refresh {region}, continuing...")
            except Exception as e:
                logger.error(f"Error in {region}: {e}")
                import traceback
                logger.error(traceback.format_exc())

        logger.info("="*60)
        logger.info("TOKEN REFRESH COMPLETE")
        logger.info("="*60)

    except Exception as e:
        logger.error(f"Critical error in refresh_all: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        is_refreshing = False

def load_tokens_from_file(region):
    """Load tokens from file for region"""
    region = region.upper()
    if region not in REGIONS:
        return []
    
    token_file = get_file_path(REGIONS[region]['tokens'])
    
    try:
        if not os.path.exists(token_file):
            return []
        
        with open(token_file, "r") as f:
            data = json.load(f)
        
        tokens = [
            item["token"] for item in data 
            if item.get("token") and len(item["token"]) > 10
        ]
        
        return tokens
    except Exception as e:
        logger.error(f"Error loading tokens for {region}: {e}")
        return []

def get_tokens_for_request(region):
    """Get next batch of tokens using rotation"""
    region = region.upper()
    
    # Initialize if needed
    if region not in token_rotation:
        tokens = load_tokens_from_file(region)
        if not tokens:
            return []
        token_rotation[region] = {
            'all_tokens': tokens,
            'current_index': 0,
            'total_tokens': len(tokens)
        }
    
    rotation = token_rotation[region]
    all_tokens = rotation['all_tokens']
    total = rotation['total_tokens']
    
    if total == 0:
        return []
    
    current = rotation['current_index']
    start = current
    end = (current + TOKENS_PER_REQUEST) % total
    
    if start < end:
        batch = all_tokens[start:end]
    else:
        batch = all_tokens[start:] + all_tokens[:end]
    
    token_rotation[region]['current_index'] = end
    
    return batch

# ==================== VISIT SYSTEM ====================
def get_url(region):
    region = region.upper()
    if region == "IND":
        return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif region in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        return "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

def parse_protobuf_response(response_data):
    """Parse protobuf safely"""
    try:
        info = Info()
        info.ParseFromString(response_data)
        
        return {
            "uid": getattr(info.AccountInfo, 'UID', 0),
            "nickname": getattr(info.AccountInfo, 'PlayerNickname', ""),
            "likes": getattr(info.AccountInfo, 'Likes', 0),
            "region": getattr(info.AccountInfo, 'PlayerRegion', ""),
            "level": getattr(info.AccountInfo, 'Levels', 0)
        }
    except Exception as e:
        logger.error(f"Protobuf parse error: {e}")
        return None

async def send_visit_request(session, url, token, uid, data):
    """Send single visit"""
    headers = {
        "ReleaseVersion": "OB52",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {token}",
        "Host": url.replace("https://", "").split("/")[0],
        "Content-Type": "application/x-protobuf",
    }
    
    try:
        async with session.post(
            url, 
            headers=headers, 
            data=data, 
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=5)
        ) as resp:
            if resp.status == 200:
                response_data = await resp.read()
                return True, response_data
            return False, None
    except Exception:
        return False, None

async def send_visits_parallel(tokens, uid, region, target=1000):
    """Send visits with detailed progress logging and region-specific handling"""
    url = get_url(region)
    logger.info(f"[SEND_VISITS] Region: {region}, URL: {url}, UID: {uid}")
    print(f"[SEND_VISITS] Region: {region} | Target: {target} visits | Tokens: {len(tokens)}", flush=True)

    connector = aiohttp.TCPConnector(
        limit=100,
        limit_per_host=50,
        ttl_dns_cache=300,
    )

    try:
        # Region-specific encryption suffix
        # BD, BR, US, NA, SAC use "1801"
        # IND might need different suffix - testing with "1801" first
        if region == "IND":
            # IND specific - might need adjustment
            suffix = "1801"  # Change this if IND needs different suffix
            logger.info(f"[SEND_VISITS] Using IND-specific encryption suffix: {suffix}")
        else:
            suffix = "1801"

        encrypt_input = "08" + Encrypt_ID(str(uid)) + suffix
        logger.info(f"[SEND_VISITS] Encrypt input: {encrypt_input[:30]}... (region: {region})")
        encrypted = encrypt_api(encrypt_input)
        data = bytes.fromhex(encrypted)
        logger.info(f"[SEND_VISITS] Encryption successful, data length: {len(data)} bytes")
        logger.info(f"[SEND_VISITS] Encrypted data (first 40 chars): {encrypted[:40]}...")
    except Exception as e:
        logger.error(f"[SEND_VISITS] Encryption error for {region}: {e}")
        print(f"[SEND_VISITS] Encryption failed: {e}", flush=True)
        import traceback
        logger.error(traceback.format_exc())
        return 0, 0, None

    total_success = 0
    total_sent = 0
    player_info = None
    batch_count = 0
    failed_requests = 0

    async with aiohttp.ClientSession(connector=connector) as session:
        logger.info(f"[SEND_VISITS] Starting visit loop - Target: {target}, Batch size: {TOKENS_PER_REQUEST}")

        while total_success < target:
            remaining = target - total_success
            batch_size = min(remaining, TOKENS_PER_REQUEST)
            batch_count += 1

            if not tokens:
                logger.warning("[SEND_VISITS] No tokens available, breaking loop")
                break

            tasks = []
            for i in range(batch_size):
                token = tokens[i % len(tokens)]
                task = asyncio.create_task(
                    send_visit_request(session, url, token, uid, data)
                )
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            batch_success = 0
            batch_failed = 0
            for result in results:
                if isinstance(result, Exception):
                    batch_failed += 1
                    failed_requests += 1
                    continue
                success, response = result
                if success:
                    batch_success += 1
                    if player_info is None and response:
                        player_info = parse_protobuf_response(response)
                        logger.info(f"[SEND_VISITS] Got player info: {player_info}")
                else:
                    batch_failed += 1
                    failed_requests += 1

            total_success += batch_success
            total_sent += batch_size

            # Log every batch for debugging
            if batch_count <= 5 or batch_count % 10 == 0 or batch_failed > 0:
                logger.info(f"[SEND_VISITS] Batch {batch_count}: {batch_success}/{batch_size} OK, {batch_failed} Failed | Total: {total_success}/{target}")
                if batch_failed > 0:
                    print(f"[SEND_VISITS] WARNING: Batch {batch_count} had {batch_failed} failures!", flush=True)

            # Print progress
            if batch_count % 10 == 0 or total_success >= target:
                print(f"[SEND_VISITS] {region} Progress: {total_success}/{target} ({(total_success/target*100):.1f}%) - Failed: {failed_requests}", flush=True)

            if total_success < target:
                await asyncio.sleep(0.05)

    logger.info(f"[SEND_VISITS] {region} Completed: {total_success}/{total_sent} successful, {failed_requests} failed")
    print(f"[SEND_VISITS] {region} Done - Success: {total_success}, Failed: {failed_requests}", flush=True)
    return total_success, total_sent, player_info

# ==================== API ROUTES ====================
@app.route('/')
def home():
    return jsonify({
        "status": "Free Fire Visit Bot - Multi-Region (Custom JWT)",
        "jwt_api": API_BASE_URL,
        "regions": list(REGIONS.keys()),
        "endpoints": {
            "/visit?region=BD&uid=123": "Send visits",
            "/refresh?region=BD": "Refresh tokens (region optional)",
            "/status": "Full status",
            "/health": "Health check",
            "/test?region=IND": "Test region tokens"
        }
    })

@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "time": datetime.now().isoformat(),
        "regions_configured": len(REGIONS),
        "last_refreshes": {k: time.ctime(v) if v else "Never" 
                          for k, v in last_token_refresh.items()}
    })

@app.route('/visit')
def visit():
    """Send visits endpoint with detailed logging"""
    region = request.args.get('region', '').upper()
    uid = request.args.get('uid', '')

    print(f"[VISIT] Request received - Region: {region}, UID: {uid}", flush=True)
    logger.info(f"="*60)
    logger.info(f"VISIT REQUEST - Region: {region}, UID: {uid}")
    logger.info(f"="*60)

    if not region or not uid:
        logger.error("[VISIT] Missing region or uid")
        return jsonify({"error": "Missing region or uid"}), 400

    if region not in REGIONS:
        logger.error(f"[VISIT] Invalid region: {region}")
        return jsonify({"error": f"Invalid region. Use: {list(REGIONS.keys())}"}), 400

    try:
        uid = int(uid)
    except ValueError:
        logger.error(f"[VISIT] Invalid UID format: {uid}")
        return jsonify({"error": "UID must be number"}), 400

    tokens = get_tokens_for_request(region)
    logger.info(f"[VISIT] Got {len(tokens)} tokens for {region}")

    if not tokens:
        logger.error(f"[VISIT] No tokens available for {region}")
        return jsonify({
            "error": "No tokens available", 
            "solution": f"Add accounts to {REGIONS[region]['accounts']} and call /refresh?region={region}"
        }), 503

    try:
        logger.info(f"[VISIT] Starting visit process for UID {uid}...")
        start_time = time.time()

        success, sent, player_info = asyncio.run(send_visits_parallel(
            tokens, uid, region, 1000
        ))

        elapsed = time.time() - start_time
        logger.info(f"[VISIT] Process completed in {elapsed:.1f}s")
        logger.info(f"[VISIT] Results: {success}/{sent} successful ({(success/max(sent,1)*100):.1f}%)")

        response = {
            "success": True,
            "region": region,
            "target_uid": uid,
            "visits_success": success,
            "visits_failed": 1000 - success,
            "efficiency": f"{(success/max(sent,1)*100):.1f}%",
            "time_taken": f"{elapsed:.1f}s"
        }

        if player_info:
            response.update({
                "player_uid": player_info.get("uid"),
                "nickname": player_info.get("nickname"),
                "level": player_info.get("level"),
                "current_likes": player_info.get("likes")
            })
            logger.info(f"[VISIT] Player: {player_info.get('nickname')} (Level {player_info.get('level')}) - Likes: {player_info.get('likes')}")

        logger.info(f"[VISIT] Response: {response}")
        print(f"[VISIT] Done - Success: {success}, Failed: {1000-success}", flush=True)
        return jsonify(response)

    except Exception as e:
        logger.error(f"[VISIT] Error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        print(f"[VISIT] Error: {e}", flush=True)
        return jsonify({"error": str(e)}), 500

@app.route('/refresh', methods=['GET', 'POST'])
def refresh():
    """Refresh tokens"""
    region = request.args.get('region', '').upper()
    
    if is_refreshing:
        return jsonify({
            "status": "refresh_in_progress",
            "message": "Another refresh is running"
        }), 429
    
    def run_refresh():
        if region and region in REGIONS:
            # Single region
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(refresh_region_tokens(region))
            finally:
                loop.close()
        else:
            # All regions
            refresh_all_tokens_sync()
    
    thread = threading.Thread(target=run_refresh)
    thread.start()
    
    return jsonify({
        "status": "refresh_started",
        "region": region or "ALL",
        "message": "Refresh running in background, check logs"
    })

@app.route('/status')
def status():
    """Get full status"""
    result = {
        "is_refreshing": is_refreshing,
        "regions": {}
    }
    
    for region in REGIONS.keys():
        # Check accounts file
        acc_file = get_file_path(REGIONS[region]['accounts'])
        acc_count = 0
        if os.path.exists(acc_file):
            try:
                with open(acc_file) as f:
                    acc_count = len([l for l in f if l.strip() and not l.startswith('#')])
            except:
                pass
        
        # Check tokens
        if region in token_rotation:
            rot = token_rotation[region]
            token_count = rot['total_tokens']
            available = True
        else:
            tokens = load_tokens_from_file(region)
            token_count = len(tokens)
            available = token_count > 0
        
        last_refresh = last_token_refresh.get(region, 0)
        
        result["regions"][region] = {
            "accounts_file": os.path.exists(acc_file),
            "accounts_count": acc_count,
            "tokens_loaded": token_count,
            "tokens_available": available,
            "last_refresh": time.ctime(last_refresh) if last_refresh else "Never",
            "minutes_ago": int((time.time() - last_refresh)/60) if last_refresh else None
        }
    
    return jsonify(result)

# ==================== AUTO REFRESH ====================
def auto_refresh():
    """Background auto-refresh - runs every 2 hours only"""
    logger.info("Auto-refresh thread started")
    print("🔄 Auto-refresh thread started (Interval: 2 hours)", flush=True)

    # Create new event loop for this thread
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        logger.info("Event loop created for auto-refresh thread")
    except Exception as e:
        logger.error(f"Failed to create event loop: {e}")
        return

    while True:
        try:
            # Sleep for 2 hours (7200 seconds) - check interval
            # But check every 5 minutes (300s) to see if we need refresh
            sleep_time = 300  # 5 minutes check interval
            total_waited = 0

            while total_waited < TOKEN_REFRESH_INTERVAL:
                time.sleep(sleep_time)
                total_waited += sleep_time

                # Check if manual refresh was done (last_token_refresh updated)
                # If so, reset our timer
                any_recent_refresh = False
                for region in REGIONS.keys():
                    last = last_token_refresh.get(region, 0)
                    if time.time() - last < sleep_time + 10:  # Refreshed in last 5 min
                        any_recent_refresh = True
                        break

                if any_recent_refresh:
                    logger.info("Manual refresh detected, resetting auto-refresh timer")
                    total_waited = 0

            # Now check if we really need refresh
            needs_refresh = False
            for region in REGIONS.keys():
                last = last_token_refresh.get(region, 0)
                if time.time() - last >= TOKEN_REFRESH_INTERVAL:
                    needs_refresh = True
                    break

            if needs_refresh and not is_refreshing:
                print(f"🔄 AUTO-REFRESH TRIGGERED AFTER {TOKEN_REFRESH_INTERVAL/3600:.1f} HOURS", flush=True)
                refresh_all_tokens_sync()
            else:
                logger.info("Auto-refresh check: No refresh needed yet")

        except Exception as e:
            logger.error(f"Auto-refresh error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            time.sleep(300)  # Wait 5 minutes on error

# ==================== STARTUP ====================
def initialize():
    """Initialize"""
    logger.info("="*60)
    logger.info("FREE FIRE VISIT BOT - MULTI REGION")
    logger.info("="*60)
    
    # Create empty account files if not exist (in same directory as script)
    logger.info(f"Script directory: {SCRIPT_DIR}")
    for region, files in REGIONS.items():
        acc_path = get_file_path(files['accounts'])
        if not os.path.exists(acc_path):
            try:
                with open(acc_path, 'w') as f:
                    f.write(f"# Add {region} accounts here (uid:password format)\n")
                logger.info(f"Created {acc_path}")
            except Exception as e:
                logger.error(f"Could not create {acc_path}: {e}")
    
    # Initial refresh - run in main thread to avoid event loop issues
    logger.info("Starting initial token refresh...")
    try:
        # For initial refresh, use the current event loop or create new one
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If loop is running (e.g., in some environments), schedule it
                logger.info("Event loop already running, refresh will run in background")
            else:
                refresh_all_tokens_sync()
        except RuntimeError:
            # No event loop exists yet, create one
            refresh_all_tokens_sync()
    except Exception as e:
        logger.error(f"Initial refresh error: {e}")
        logger.info("Continuing without initial refresh - use /refresh endpoint manually")
    
    # Start auto-refresh
    t = threading.Thread(target=auto_refresh, daemon=True)
    t.start()

initialize()


@app.route('/test')
def test_region():
    """Test if region tokens are working"""
    region = request.args.get('region', '').upper()

    if not region or region not in REGIONS:
        return jsonify({"error": f"Invalid region. Use: {list(REGIONS.keys())}"}), 400

    # Load tokens
    tokens = get_tokens_for_request(region)

    if not tokens:
        return jsonify({
            "region": region,
            "status": "error",
            "message": "No tokens available",
            "solution": f"Run /refresh?region={region} first"
        }), 503

    # Test the URL
    url = get_url(region)

    return jsonify({
        "region": region,
        "status": "ok",
        "tokens_available": len(tokens),
        "api_url": url,
        "accounts_file": REGIONS[region]['accounts'],
        "token_file": REGIONS[region]['tokens'],
        "message": f"{region} has {len(tokens)} tokens ready"
    })

# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    # للتوافق مع Render - استخدم المنفذ الذي يوفره
    port = int(os.environ.get("PORT", 5070))
    logger.info(f"Starting server on port {port}")
    
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        threaded=True,
        use_reloader=False
    )