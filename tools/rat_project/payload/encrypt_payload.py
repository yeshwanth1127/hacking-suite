# encrypt_payload.py
from cryptography.fernet import Fernet
import sys
import os

def main():
    key_file = "fernet.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)

    fernet = Fernet(key)
    with open(sys.argv[1], "rb") as infile:
        encrypted = fernet.encrypt(infile.read())
    with open(sys.argv[2], "wb") as outfile:
        outfile.write(encrypted)
    print(f"[+] Encrypted successfully. Output: {sys.argv[2]}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: encrypt_payload.py <input.dll> <output.bin>")
        sys.exit(1)
    main()
