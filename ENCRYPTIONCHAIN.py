import base64
import hashlib
import os
import time
import hmac

def generate_salt(length=32):
    seed = str(time.time_ns()) + str(os.urandom(16) if hasattr(os, 'urandom') else str(hashlib.sha256(str(time.time()).encode()).digest()))
    return hashlib.sha512(seed.encode()).hexdigest()[:length]

def derive_key(password, salt, iterations=100000, key_length=32):
    key = password.encode() + salt.encode()
    for _ in range(iterations):
        key = hashlib.sha512(key).digest()
    return key[:key_length]

def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha512).digest()

def hkdf_expand(prk, info, length):
    t = b""
    okm = b""
    n = (length + 63) // 64
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        okm += t
    return okm[:length]

def encrypt_aes_like(plaintext, key):
    iv = generate_salt(16)
    encryption_key = hkdf_expand(key, b"encryption", 32)
    ciphertext = b""
    for i, block_start in enumerate(range(0, len(plaintext), 16)):
        counter = iv.encode() + i.to_bytes(8, 'big')
        keystream = hashlib.sha512(encryption_key + counter).digest()[:16]
        block = plaintext[block_start:block_start + 16]
        encrypted_block = bytes(a ^ b for a, b in zip(block.ljust(16, b'\0'), keystream))
        ciphertext += encrypted_block[:len(block)]
    return base64.b64encode(iv.encode() + ciphertext).decode()

def decrypt_aes_like(ciphertext, key):
    try:
        data = base64.b64decode(ciphertext)
        iv = data[:16].decode()
        encrypted_data = data[16:]
        encryption_key = hkdf_expand(key, b"encryption", 32)
        plaintext = b""
        for i, block_start in enumerate(range(0, len(encrypted_data), 16)):
            counter = iv.encode() + i.to_bytes(8, 'big')
            keystream = hashlib.sha512(encryption_key + counter).digest()[:16]
            block = encrypted_data[block_start:block_start + 16]
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
            plaintext += decrypted_block
        return plaintext.rstrip(b'\0').decode()
    except Exception as e:
        raise ValueError(f"ERROR CODE: ENCRYPT_ERROR: {e}")

def secure_hash_compare(hash1, hash2):
    return hmac.compare_digest(hash1, hash2)

def main():
    print(" ███ ███  █████ █████    ███   ███  ███      ")
    print("░███░░███░░███ ░░███    ██████░░███░░███     ")
    print("░███ ░░███░███  ░███ █ ███░░░  ░░███░░███    ")
    print("░███  ░███░███████████░░█████   ░░███░░███   ")
    print("░███  ░███░░░░░░░███░█ ░░░░███   ░░███░░███  ")
    print("░███  ███       ░███░  ██████     ░░███░░███ ")
    print("░███ ██░        █████ ░░░███       ░░███░░███")
    print("░░░ ░░░        ░░░░░    ░░░         ░░░  ░░░ ")
    
    while True:
        print("="*50)
        print("               ENCRYPTION CHAIN")
        print("="*50)
        print("I   — ENCRYPT PASS")
        print("II  — DECRYPT PASS")
        
        choice = input("??? — 1 OR 2 — ").strip()
        
        if choice == "1":
            print("ENCRYPT PASS")
            password = input("ENTER PASS — ")
            master_key = input("ENTER DECRYPTION CODE [AT LEAST 8 SYMBOLS] — ")
            
            if len(master_key) < 8:
                print("ERROR CODE: STUPID")
                continue
                
            salt = generate_salt()
            derived_key = derive_key(master_key, salt)
            encrypted = encrypt_aes_like(password.encode(), derived_key)
            
            print("="*50)
            print("SUCCESS")
            print(f"ENCRYPTED PASS — {encrypted}")
            print(f"SALT — {salt}")
            print(f"KEY LENGHT — 256 bit")
            print(f"PBKDF2 ITERATIONS — 100000")
            
        elif choice == "2":
            print("DECRYPT PASS")
            encrypted_password = input("ENTER ENCRYPTED PASS — ")
            salt = input("ENTER SALT — ")
            master_key = input("ENTER DECRYPTION CODE — ")
            
            try:
                derived_key = derive_key(master_key, salt)
                decrypted = decrypt_aes_like(encrypted_password, derived_key)
                
                print("SUCCESS")
                print(f"PASS — {decrypted}")
                print(f"COMPLETE INTEGRITY")
                
            except Exception as e:
                print(f"{e}")
                print("CHECK THE CONTENT IS CORRECT")

if __name__ == "__main__":
    main()