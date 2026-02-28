# shift_cipher.py
from crypto_utils import char_to_index, index_to_lower_char, index_to_upper_char

def encrypt_shift(plaintext, key):
    try: k = int(key)
    except: raise ValueError("Key must be an integer.")
    res, steps = [], []
    for ch in plaintext:
        idx = char_to_index(ch)
        if idx == -1: res.append(ch)
        else:
            new_idx = (idx + k) % 26
            new_char = index_to_upper_char(new_idx)
            res.append(new_char)
            steps.append(f"'{ch}' (index {idx}) + {k} = {idx+k} | mod 26 = {new_idx} → '{new_char}'")
    return {"text": "".join(res), "steps": steps}

def decrypt_shift(ciphertext, key):
    try: k = int(key)
    except: raise ValueError("Key must be an integer.")
    res, steps = [], []
    for ch in ciphertext:
        idx = char_to_index(ch)
        if idx == -1: res.append(ch)
        else:
            new_idx = (idx - k) % 26
            new_char = index_to_lower_char(new_idx)
            res.append(new_char)
            steps.append(f"'{ch}' (index {idx}) - {k} = {idx-k} | mod 26 = {new_idx} → '{new_char}'")
    return {"text": "".join(res), "steps": steps}