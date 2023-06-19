import pyotp
import hashlib
import random
import string
import datetime

# Kullanıcı veritabanı
users = {}

# Günlük kayıt dosyası
log_file = "log.txt"

# Kullanıcı kaydı
def register_user(username, password):
    if username in users:
        return "Kullanıcı adı zaten mevcut."
    
    # Şifre karma (hashing) işlemi
    hashed_password = hash_password(password)
    
    # Kullanıcıyı kaydetme
    users[username] = {
        "password": hashed_password,
        "2fa_enabled": False,
        "2fa_secret": None,
        "login_attempts": 0
    }
    
    return "Kullanıcı kaydedildi."

# Kullanıcı girişi
def login(username, password, verification_code=None):
    if username not in users:
        return "Kullanıcı adı bulunamadı."

    user = users[username]

    # Kullanıcının hesabı kilitliyse çıkış yap
    if user["login_attempts"] >= 3:
        return "Hesabınız kilitli. Şifrenizi sıfırlayın."

    # Şifre doğrulama
    if not verify_password(password, user["password"]):
        user["login_attempts"] += 1
        return "Hatalı şifre. Kalan deneme sayısı: {}".format(3 - user["login_attempts"])

    # İki aşamalı doğrulama kontrolü
    if user["2fa_enabled"]:
        if verification_code is None:
            return "İki aşamalı doğrulama kodu gerekiyor."

        if not verify_2fa_code(verification_code, user["2fa_secret"]):
            return "Hatalı iki aşamalı doğrulama kodu."

    # Başarılı giriş
    user["login_attempts"] = 0
    return "Giriş başarılı."

# Şifre sıfırlama
def reset_password(username, new_password):
    if username not in users:
        return "Kullanıcı adı bulunamadı."
    
    hashed_password = hash_password(new_password)
    users[username]["password"] = hashed_password
    
    return "Şifre sıfırlandı."

# İki aşamalı doğrulama kodu oluşturma
def generate_2fa_code():
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.now()

# İki aşamalı doğrulama kodunu doğrulama
def verify_2fa_code(code, secret_key):
    totp = pyotp.TOTP(secret_key)
    return totp.verify(code)

# Şifre karma (hashing)
def hash_password(password):
    salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16)).encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed_password.hex()

# Şifre doğrulama
def verify_password(password, hashed_password):
    salt = bytes.fromhex(hashed_password)[:16]
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed_password == password_hash.hex()

# Günlük kaydı oluşturma
def create_log_entry(username, action):
    timestamp = datetime.datetime.now()
    log_entry = f"[{timestamp}] Kullanıcı '{username}', '{action}' işlemini gerçekleştirdi."
    
    with open(log_file, "a") as log:
        log.write(log_entry + "\n")
    
    print("Günlük kaydı oluşturuldu.")

# Örnek kullanım
username = "example_user"
password = "example_password"
new_password = "new_example_password"

register_user(username, password)
login(username, password)
verification_code = generate_2fa_code()
login(username, password, verification_code)
reset_password(username, new_password)
create_log_entry(username, "Şifre sıfırlama")
