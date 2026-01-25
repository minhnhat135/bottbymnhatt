import logging
import re
import asyncio
import time
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

# ==============================================================================
# 1. CẤU HÌNH BOT
# ==============================================================================
BOT_TOKEN = "8414556300:AAGs-pW76xOmEzi-SbLcHDaUOiUXtYpBq_0"  # Thay token của bạn vào đây

# Cấu hình logging để theo dõi lỗi
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ==============================================================================
# 2. CÁC HÀM XỬ LÝ CHUỖI (THEO YÊU CẦU CỦA BẠN)
# ==============================================================================

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

# ==============================================================================
# 3. LOGIC XỬ LÝ CHÍNH & RETRY (MÔ PHỎNG)
# ==============================================================================

async def process_card_with_retry(card_data, update: Update):
    """
    Hàm xử lý logic chính với cơ chế Retry 20 lần.
    """
    cc, mm, yyyy, cvc = card_data.split('|')
    
    # Kiểm tra Luhn trước khi chạy
    if not validate_luhn(cc):
        return f"❌ <b>INVALID LUHN</b>: {cc}"

    max_retries = 20
    
    # Gửi thông báo đang xử lý
    msg = await update.message.reply_text(f"🔄 Processing: {cc[:4]}... | 0/{max_retries}")

    for attempt in range(1, max_retries + 1):
        try:
            # === [PLACEHOLDER] LOGIC CỦA BẠN SẼ NẰM Ở ĐÂY ===
            # Thay vì gọi request thật, ta dùng hàm giả lập này.
            # Trong thực tế, bạn sẽ gọi requests.post(...) ở đây.
            
            # Giả lập độ trễ mạng
            await asyncio.sleep(1) 
            
            # --- Giả lập các tình huống trả về ---
            # Để test retry, ta giả lập lỗi ngẫu nhiên hoặc trạng thái 3DS
            import random
            simulated_result = random.choice([
                "Authorised", 
                "NetworkError", 
                "ChallengeShopper", # 3DS case
                "IdentifyShopper",  # 3DS case
                "MissingToken",     # Error case
                "Refused"
            ])
            
            # LOGIC XỬ LÝ KẾT QUẢ (Dựa trên yêu cầu của bạn)
            status = "UNKNOWN"
            
            # 1. Trường hợp thành công
            if simulated_result == "Authorised":
                return f"✅ <b>APPROVED</b>: {card_data} - Charged Successfully"

            # 2. Trường hợp Refused (Dừng, không retry)
            elif simulated_result == "Refused":
                return f"❌ <b>DECLINED</b>: {card_data} - Refused by Bank"

            # 3. Các trường hợp cần RETRY (Lỗi mạng, Token, 3DS)
            retry_conditions = [
                "NetworkError", 
                "MissingToken", 
                "ChallengeShopper", 
                "IdentifyShopper", 
                "RedirectShopper"
            ]
            
            if simulated_result in retry_conditions:
                # Nếu chưa hết lượt retry, tiếp tục vòng lặp
                if attempt < max_retries:
                    await msg.edit_text(f"⚠️ Retry {attempt}/{max_retries}: {simulated_result} - {cc[:4]}...")
                    await asyncio.sleep(2) # Nghỉ 2s trước khi thử lại
                    continue
                else:
                    return f"dead <b>TIMEOUT</b>: {card_data} - Failed after {max_retries} retries ({simulated_result})"
            
            # Các lỗi khác không xác định
            return f"❓ <b>UNKNOWN</b>: {card_data} - {simulated_result}"

        except Exception as e:
            # Bắt lỗi crash code (Network exceptions...)
            if attempt < max_retries:
                await msg.edit_text(f"⚠️ Exception {attempt}/{max_retries}: {str(e)}")
                await asyncio.sleep(2)
                continue
            return f"❌ <b>ERROR</b>: {card_data} - System Error: {str(e)}"

    return f"❌ <b>FAILED</b>: {card_data} - Unknown Error"

# ==============================================================================
# 4. HANDLERS TELEGRAM
# ==============================================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Xử lý lệnh /st"""
    await update.message.reply_text(
        "⚡ <b>Bot Ready!</b>\n"
        "Gửi danh sách thẻ (Format: cc|mm|yy|cvv) để bắt đầu.",
        parse_mode="HTML"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Nhận tin nhắn chứa list thẻ và xử lý"""
    text = update.message.text
    
    # 1. Trích xuất thẻ từ tin nhắn
    cards = extract_cards_from_text(text)
    
    if not cards:
        await update.message.reply_text("❌ Không tìm thấy thẻ hợp lệ trong tin nhắn.")
        return

    await update.message.reply_text(f"🔍 Tìm thấy {len(cards)} thẻ. Bắt đầu xử lý...")

    # 2. Duyệt qua từng thẻ và chạy logic
    for card in cards:
        result_text = await process_card_with_retry(card, update)
        # Gửi kết quả cuối cùng
        await update.message.reply_text(result_text, parse_mode="HTML")

# ==============================================================================
# 5. MAIN EXECUTION
# ==============================================================================

if __name__ == '__main__':
    print("Bot is starting...")
    # Xây dựng ứng dụng
    application = ApplicationBuilder().token(BOT_TOKEN).build()

    # Thêm Handlers
    application.add_handler(CommandHandler("st", start_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    # Chạy Bot (Polling)
    application.run_polling()
