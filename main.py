def gost_encrypt(text, key):
    block_size = 8  # Размер блока данных в байтах
    round_keys = generate_round_keys(key)
    ciphertext = []

    for i in range(0, len(text), block_size):
        block = text[i:i + block_size]
        block = [ord(char) for char in block]

        for _ in range(3):
            for j in range(8):
                block = gost_round(block, round_keys[j])
        
        block = gost_round(block, round_keys[7], last_round=True)
        ciphertext.extend(block)
    
    return bytes(ciphertext)

def gost_decrypt(ciphertext, key):
    block_size = 8
    round_keys = generate_round_keys(key)
    plaintext = []

    for i in range(0, len(ciphertext), block_size):
        block = list(ciphertext[i:i + block_size])

        block = gost_round(block, round_keys[7], last_round=True, decrypt=True)
        for _ in range(3):
            for j in range(7, -1, -1):
                block = gost_round(block, round_keys[j], decrypt=True)

        plaintext.extend(block)

    return bytes(plaintext).decode('utf-8', errors='ignore')

def gost_round(block, round_key, last_round=False, decrypt=False):
    sbox = [
        [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
        [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
        [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
        [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
        [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
        [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
        [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
        [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
    ]

    for i in range(len(block)):
        block[i] ^= round_key[i]

    for i in range(0, 8, 2):
        x, y = block[i], block[i + 1]
        if decrypt and not last_round:
            x, y = y, x  # Меняем местами x и y при дешифровке, кроме последнего раунда

        sbox_row = (x << 1) | y
        sbox_value = sbox[i // 2][sbox_row]
        sbox_bits = [int(bit) for bit in format(sbox_value, '04b')]
        
        if decrypt and not last_round:
            sbox_bits = sbox_bits[::-1]  # Переворачиваем биты при дешифровке

        for j in range(4):
            block[i + j] = sbox_bits[j] ^ block[i + j]

    if not last_round:
        block = block[4:] + block[:4]  # Циклический сдвиг на 32 бита

    return block

def generate_round_keys(key):
    key_blocks = [key[i:i + 4] for i in range(0, len(key), 4)]
    round_keys = []

    for i in range(8):
        round_keys.append(list(key_blocks[i % len(key_blocks)]))
    
    return round_keys

if __name__ == "__main__":
    choice = input("Выберите действие (шифровать - 'e', дешифровать - 'd'): ")
    key = input("Введите ключ (32 байта): ")

    if choice == 'e':
        text = input("Введите текст для шифрования: ")
        ciphertext = gost_encrypt(text, key)
        print("Зашифрованный текст:", ciphertext.hex())
    elif choice == 'd':
        ciphertext_hex = input("Введите зашифрованный текст (в шестнадцатеричной форме): ")
        ciphertext = bytes.fromhex(ciphertext_hex)
        decrypted_text = gost_decrypt(ciphertext, key)
        print("Расшифрованный текст:", decrypted_text)
    else:
        print("Неверный выбор действия. Пожалуйста, введите 'e' для шифрования или 'd' для дешифрования.")
