import requests


Q = 2 ** 64
P = 2 ** 10
FLAG_LENGTH = 40
ADDEND = 10

API_URL = "http://127.0.0.1:8000"
ENCRYPTED_FLAG_URL = f"{API_URL}/encryptedFlag"
DECRYPT_URL = f"{API_URL}/decrypt"


def get_encrypted_flag():
    result = requests.get(ENCRYPTED_FLAG_URL)
    return result.json()


def decrypt(data):
    result = requests.post(DECRYPT_URL, json=data)
    return result.json()


if __name__ == "__main__":
    encrypted_flag_json = get_encrypted_flag()
    for i in range(FLAG_LENGTH):
        encrypted_flag_json["b"]["coefficients"][i] += ADDEND * int(Q / P)
        encrypted_flag_json["b"]["coefficients"][i] %= Q
    coeffs = decrypt(encrypted_flag_json)
    flag = "".join([chr((c - ADDEND) % P) for c in coeffs[:FLAG_LENGTH]])
    print(f"Flag: {flag}")
