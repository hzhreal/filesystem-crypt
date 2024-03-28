import os
import hmac
import hashlib
import sys
import secrets
import time
from Crypto.Cipher import AES

N_ROUND: int = 5
NONCE_LEN: int = 16

def main(argv: list[str]) -> None:
    if len(argv) != 4:
        print_usage(argv)

    opt: str = argv[1]
    if opt.lower() != "-d" and opt.lower() != "-e":
        print_usage(argv)

    key: str = argv[2]
    key: bytes = hexstr_to_bytes(key)
    if key == -1:
        print("Invalid key, it must be in hex.\n")
        exit(1)
    key = calc_hash_nokey(key)

    hmac_sha1_key: str = argv[3]
    hmac_sha1_key: bytes = hexstr_to_bytes(hmac_sha1_key)
    if hmac_sha1_key == -1:
        print("Invalid hash key, it must be in hex.\n")
        exit(1)
    hmac_sha1_key = calc_hash_nokey(hmac_sha1_key)

    filePaths: list[str] = list_files(".")
    
    if not len(filePaths) >= 1:
        print("No files found.\n")
        exit(1)


    for file in filePaths:
        data: bytearray = read_file(file)
        if opt.lower() == "-d":
            print(f"Decrypting {file}...")
            try:
                nonce = data[:NONCE_LEN]
                data_without_chks = data[NONCE_LEN:-20]
                chks = data[-20:]
            except IndexError:
                print(f"{file} has been tampered with, skipping...\n")
                continue

            decrypted_data: bytes = gcm_decrypt(data_without_chks, key, nonce)
            decrypted_data += chks

            decrypted_data_final: bytes = check_hash(decrypted_data, hmac_sha1_key)

            if decrypted_data_final != b"":
                write_file(file, decrypted_data_final)
                print(f"Successfully wrote decrypted data to {file}.\n")
            else:
                print(f"{file} has been tampered with, skipping...\n")
        
        else:
            print(f"Encrypting {file}...")
            nonce: bytes = secrets.token_bytes(NONCE_LEN)
            chks: bytes = calc_hash(data, hmac_sha1_key)

            encrypted_data: bytes = gcm_encrypt(data, key, nonce)
            encrypted_data_final = nonce + encrypted_data + chks

            write_file(file, encrypted_data_final)
            print(f"Successfully wrote encrypted data to {file}.\n")

def gcm_encrypt(plaintext: bytearray, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    encrypted_data: bytes = cipher.encrypt(plaintext)
    return encrypted_data

def gcm_decrypt(ciphertext: bytearray, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    decrypted_data: bytes = cipher.decrypt(ciphertext)
    return decrypted_data

def calc_hash(data: bytearray, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha1).digest()

def calc_hash_nokey(data: bytes) -> bytes:
    msg: bytes = data
    for _ in range(N_ROUND):
        hashed: bytes = hashlib.sha256(msg).digest()
        msg = hashed
    return msg

def check_hash(data: bytearray, key: bytes) -> bytes:
    try:
        current_chks = data[-20:]
        real_data = data[:-20]
    except IndexError:
        return b""
    
    chks = calc_hash(real_data, key)

    if chks == current_chks:
        return real_data
    else:
        return b""


def list_files(path: str, filePaths: list[str] | None = None) -> list[str]:
    if filePaths is None:
        filePaths: list[str] = []
    
    files: list[str] = os.listdir(path)

    for file in files:
        file_path: str = os.path.join(path, file)
        if os.path.isfile(file_path) and file != os.path.basename(__file__):
            filePaths.append(file_path)
        
        elif os.path.isdir(file_path):
            list_files(file_path, filePaths)

    return filePaths

def hexstr_to_bytes(val: str) -> bytes | int:
    try:
        prefix: str = val[:2]
        if prefix.lower() == "0x":
            val: str = val[2:]
    except IndexError:
        return -1

    try:
        retval: bytes = bytes.fromhex(val)
    except ValueError:
        return -1
    
    return retval

def read_file(file_path: str) -> bytearray:
    with open(file_path, "rb") as file:
        data: bytearray = bytearray(file.read())
    return data

def write_file(file_path: str, data) -> None:
    with open(file_path, "wb") as file:
        file.write(data)

def print_usage(argv: list[str]) -> None:
    print(f"{argv[0]} <-d/-e> <key: 0x> <hash_key: 0x>\n")
    exit(1)

if __name__ == "__main__":
    start = time.time()
    main(sys.argv)
    end = time.time()
    print(f"\nOperation finished after {round(end - start, 2)} seconds.")