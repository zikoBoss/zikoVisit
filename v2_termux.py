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

def parse_response_simple():
    """Return simple default player info (bypass protobuf)"""
    return {
        "uid": 0,
        "nickname": "Player",
        "likes": 0,
        "region": "BD",
        "level": 1
    }

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
                return True
            return False
    except Exception:
        return False

async def send_visits_parallel(tokens, uid, region, target=1000):
    """Send visits with detailed progress logging"""
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
        suffix = "1801"
        encrypt_input = "08" + Encrypt_ID(str(uid)) + suffix
        encrypted = encrypt_api(encrypt_input)
        data = bytes.fromhex(encrypted)
    except Exception as e:
        logger.error(f"[SEND_VISITS] Encryption error: {e}")
        return 0, 0, None

    total_success = 0
    total_sent = 0
    player_info = None
    batch_count = 0
    failed_requests = 0

    async with aiohttp.ClientSession(connector=connector) as session:
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
                if result:
                    batch_success += 1
                    if player_info is None:
                        player_info = parse_response_simple()
                else:
                    batch_failed += 1
                    failed_requests += 1

            total_success += batch_success
            total_sent += batch_size

            # Log progress
            if batch_count % 10 == 0 or total_success >= target:
                print(f"[SEND_VISITS] {region} Progress: {total_success}/{target} ({(total_success/target*100):.1f}%) - Failed: {failed_requests}", flush=True)

            if total_success < target:
                await asyncio.sleep(0.05)

    logger.info(f"[SEND_VISITS] {region} Completed: {total_success}/{total_sent} successful")
    return total_success, total_sent, player_info

# ==================== API ROUTES ====================
@app.route('/')
def home():
    return jsonify({
        "status": "Free Fire Visit Bot - Multi-Region",
        "regions": list(REGIONS.keys()),
        "endpoints": {
            "/visit?region=BD&uid=123": "Send visits",
            "/refresh?region=BD": "Refresh tokens",
            "/status": "Full status",
            "/health": "Health check"
        }
    })

@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "time": datetime.now().isoformat(),
        "last_refreshes": {k: time.ctime(v) if v else "Never" 
                          for k, v in last_token_refresh.items()}
    })

@app.route('/visit')
def visit():
    region = request.args.get('region', '').upper()
    uid = request.args.get('uid', '')

    if not region or not uid:
        return jsonify({"error": "Missing region or uid"}), 400

    if region not in REGIONS:
        return jsonify({"error": f"Invalid region. Use: {list(REGIONS.keys())}"}), 400

    try:
        uid = int(uid)
    except ValueError:
        return jsonify({"error": "UID must be number"}), 400

    tokens = get_tokens_for_request(region)

    if not tokens:
        return jsonify({
            "error": "No tokens available", 
            "solution": f"Add accounts to {REGIONS[region]['accounts']} and call /refresh?region={region}"
        }), 503

    try:
        start_time = time.time()
        success, sent, player_info = asyncio.run(send_visits_parallel(
            tokens, uid, region, 1000
        ))
        elapsed = time.time() - start_time

        response = {
            "success": True,
            "region": region,
            "target_uid": uid,
            "visits_success": success,
            "visits_failed": 1000 - success,
            "time_taken": f"{elapsed:.1f}s"
        }

        if player_info:
            response.update(player_info)

        return jsonify(response)

    except Exception as e:
        logger.error(f"[VISIT] Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/refresh', methods=['GET', 'POST'])
def refresh():
    region = request.args.get('region', '').upper()
    
    if is_refreshing:
        return jsonify({"status": "refresh_in_progress"}), 429
    
    def run_refresh():
        if region and region in REGIONS:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(refresh_region_tokens(region))
            finally:
                loop.close()
        else:
            refresh_all_tokens_sync()
    
    thread = threading.Thread(target=run_refresh)
    thread.start()
    
    return jsonify({"status": "refresh_started", "region": region or "ALL"})

@app.route('/status')
def status():
    result = {"is_refreshing": is_refreshing, "regions": {}}
    
    for region in REGIONS.keys():
        acc_file = get_file_path(REGIONS[region]['accounts'])
        acc_count = 0
        if os.path.exists(acc_file):
            try:
                with open(acc_file) as f:
                    acc_count = len([l for l in f if l.strip() and not l.startswith('#')])
            except:
                pass
        
        if region in token_rotation:
            token_count = token_rotation[region]['total_tokens']
        else:
            tokens = load_tokens_from_file(region)
            token_count = len(tokens)
        
        last_refresh = last_token_refresh.get(region, 0)
        
        result["regions"][region] = {
            "accounts_count": acc_count,
            "tokens_loaded": token_count,
            "last_refresh": time.ctime(last_refresh) if last_refresh else "Never"
        }
    
    return jsonify(result)

# ==================== AUTO REFRESH ====================
def auto_refresh():
    logger.info("Auto-refresh thread started")
    while True:
        try:
            time.sleep(TOKEN_REFRESH_INTERVAL)
            if not is_refreshing:
                refresh_all_tokens_sync()
        except Exception as e:
            logger.error(f"Auto-refresh error: {e}")
            time.sleep(300)

# ==================== STARTUP ====================
def initialize():
    logger.info("="*60)
    logger.info("FREE FIRE VISIT BOT - MULTI REGION")
    logger.info("="*60)
    
    # Start auto-refresh
    t = threading.Thread(target=auto_refresh, daemon=True)
    t.start()

initialize()

# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5070))
    logger.info(f"Starting server on port {port}")
    
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        threaded=True,
        use_reloader=False
    )