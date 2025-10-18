#!/usr/bin/env python3
"""
Программа для шифрования и дешифрования данных с использованием асимметричных ключей.
Поддерживает режимы CLI и генерацию пары ключей.
"""

import argparse
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets


def generate_key_pair():
    """
    Генерирует пару RSA-ключей (приватный и публичный)
    """
    # Генерируем приватный ключ
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Можно увеличить до 4096 для большей безопасности
        backend=default_backend()
    )
    
    # Получаем публичный ключ из приватного
    public_key = private_key.public_key()
    
    return private_key, public_key


def save_private_key(private_key, filepath):
    """
    Сохраняет приватный ключ в файл
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(filepath, 'wb') as f:
        f.write(pem)


def save_public_key(public_key, filepath):
    """
    Сохраняет публичный ключ в файл
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(filepath, 'wb') as f:
        f.write(pem)


def load_private_key(filepath):
    """
    Загружает приватный ключ из файла
    """
    with open(filepath, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def load_public_key(filepath):
    """
    Загружает публичный ключ из файла
    """
    with open(filepath, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key


def encrypt_data(public_key, data):
    """
    Шифрует данные с использованием публичного ключа.
    Использует гибридный метод: RSA для шифрования симметричного ключа, AES для шифрования данных.
    """
    # Генерируем случайный симметричный ключ для AES
    symmetric_key = secrets.token_bytes(32)  # 256 бит для AES-256
    
    # Шифруем симметричный ключ с помощью публичного RSA-ключа
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Генерируем случайный IV для AES
    iv = secrets.token_bytes(16)  # 128 бит для AES
    
    # Создаем шифр AES в режиме CBC
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Добавляем padding для соответствия размера блока AES (16 байт)
    padded_data = _pad_data(data)
    
    # Шифруем данные
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Комбинируем зашифрованный симметричный ключ, IV и зашифрованные данные
    result = encrypted_symmetric_key + iv + encrypted_data
    
    return result


def decrypt_data(private_key, encrypted_data):
    """
    Дешифрует данные с использованием приватного ключа.
    Использует гибридный метод: RSA для дешифрования симметричного ключа, AES для дешифрования данных.
    """
    # Размеры компонентов
    rsa_key_size = (private_key.key_size // 8)  # Размер в байтах
    iv_size = 16  # 128 бит для AES
    
    # Извлекаем зашифрованный симметричный ключ
    encrypted_symmetric_key = encrypted_data[:rsa_key_size]
    remaining_data = encrypted_data[rsa_key_size:]
    
    # Извлекаем IV
    iv = remaining_data[:iv_size]
    encrypted_content = remaining_data[iv_size:]
    
    # Дешифруем симметричный ключ с помощью приватного RSA-ключа
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Создаем шифр AES в режиме CBC
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Дешифруем данные
    padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
    
    # Убираем padding
    original_data = _unpad_data(padded_data)
    
    return original_data


def _pad_data(data):
    """
    Добавляет padding к данным для соответствия размера блока AES (16 байт)
    """
    block_size = 16
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def _unpad_data(padded_data):
    """
    Убирает padding из данных
    """
    padding_len = padded_data[-1]
    return padded_data[:-padding_len]


def encrypt_file(input_file, output_file, public_key_path):
    """
    Шифрует содержимое файла
    """
    # Загружаем публичный ключ
    public_key = load_public_key(public_key_path)
    
    # Читаем содержимое входного файла
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Шифруем данные
    encrypted_data = encrypt_data(public_key, data)
    
    # Сохраняем зашифрованные данные в выходной файл
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)


def decrypt_file(input_file, output_file, private_key_path):
    """
    Дешифрует содержимое файла
    """
    # Загружаем приватный ключ
    private_key = load_private_key(private_key_path)
    
    # Читаем зашифрованные данные из входного файла
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    
    # Дешифруем данные
    decrypted_data = decrypt_data(private_key, encrypted_data)
    
    # Сохраняем расшифрованные данные в выходной файл
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)


def encrypt_message(message, public_key_path):
    """
    Шифрует текстовое сообщение
    """
    # Загружаем публичный ключ
    public_key = load_public_key(public_key_path)
    
    # Конвертируем сообщение в байты
    data = message.encode('utf-8')
    
    # Шифруем данные
    encrypted_data = encrypt_data(public_key, data)
    
    # Кодируем в base64 для удобного вывода
    return base64.b64encode(encrypted_data).decode('utf-8')


def decrypt_message(encrypted_message, private_key_path):
    """
    Дешифрует текстовое сообщение
    """
    # Декодируем из base64
    encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
    
    # Загружаем приватный ключ
    private_key = load_private_key(private_key_path)
    
    # Дешифруем данные
    decrypted_data = decrypt_data(private_key, encrypted_data)
    
    # Конвертируем в строку
    return decrypted_data.decode('utf-8')


def generate_keys():
    """
    Генерирует новую пару ключей и сохраняет их в соответствующие директории
    """
    private_key, public_key = generate_key_pair()
    
    # Создаем директории, если они не существуют
    os.makedirs('privatekeys', exist_ok=True)
    os.makedirs('pubkeys', exist_ok=True)
    
    # Сохраняем приватный ключ в директорию privatekeys
    private_key_path = f"privatekeys/private_key_{secrets.token_hex(4)}.pem"
    save_private_key(private_key, private_key_path)
    
    # Сохраняем публичный ключ в директорию pubkeys
    public_key_path = f"pubkeys/public_key_{secrets.token_hex(4)}.pem"
    save_public_key(public_key, public_key_path)
    
    print(f"Ключи успешно сгенерированы:")
    print(f"Приватный ключ: {private_key_path}")
    print(f"Публичный ключ: {public_key_path}")


def main():
    parser = argparse.ArgumentParser(description='Программа для шифрования и дешифрования данных с использованием асимметричных ключей')
    
    # Опциональные аргументы
    parser.add_argument('-d', action='store_true', help='Режим дешифрования (без флага - режим шифрования)')
    parser.add_argument('-i', dest='key_path', help='Путь до приватного/публичного ключа')
    parser.add_argument('-in', dest='input_file', help='Входной файл')
    parser.add_argument('-out', dest='output_file', help='Выходной файл')
    parser.add_argument('-m', dest='message', help='Текстовое сообщение для шифрования/дешифрования')
    parser.add_argument('-g', action='store_true', help='Генерация новой пары ключей')
    
    args = parser.parse_args()
    
    # Если указан флаг генерации ключей
    if args.g:
        generate_keys()
        return
    
    # Проверяем обязательные аргументы в зависимости от режима
    if not args.d:  # Режим шифрования
        if not args.key_path:
            print("Ошибка: Не указан путь к публичному ключу (-i)")
            return
        
        if not args.input_file and not args.message:
            print("Ошибка: Не указан входной файл (-in) или сообщение (-m)")
            return
        
        if args.input_file and args.message:
            print("Ошибка: Указаны одновременно входной файл и сообщение")
            return
        
        # Шифрование файла
        if args.input_file:
            if not args.output_file:
                print("Ошибка: Не указан выходной файл (-out)")
                return
            
            if not os.path.exists(args.input_file):
                print(f"Ошибка: Входной файл не найден: {args.input_file}")
                return
            
            if not os.path.exists(args.key_path):
                print(f"Ошибка: Ключ не найден: {args.key_path}")
                return
            
            encrypt_file(args.input_file, args.output_file, args.key_path)
            print(f"Файл успешно зашифрован: {args.output_file}")
        
        # Шифрование сообщения
        elif args.message:
            encrypted_message = encrypt_message(args.message, args.key_path)
            
            if args.output_file:
                with open(args.output_file, 'w') as f:
                    f.write(encrypted_message)
                print(f"Сообщение успешно зашифровано и сохранено в: {args.output_file}")
            else:
                print(encrypted_message)
    
    else:  # Режим дешифрования
        if not args.key_path:
            print("Ошибка: Не указан путь к приватному ключу (-i)")
            return
        
        if not args.input_file and not args.message:
            print("Ошибка: Не указан входной файл (-in) или сообщение (-m)")
            return
        
        if args.input_file and args.message:
            print("Ошибка: Указаны одновременно входной файл и сообщение")
            return
        
        # Дешифрование файла
        if args.input_file:
            if not args.output_file:
                print("Ошибка: Не указан выходной файл (-out)")
                return
            
            if not os.path.exists(args.input_file):
                print(f"Ошибка: Входной файл не найден: {args.input_file}")
                return
            
            if not os.path.exists(args.key_path):
                print(f"Ошибка: Ключ не найден: {args.key_path}")
                return
            
            decrypt_file(args.input_file, args.output_file, args.key_path)
            print(f"Файл успешно дешифрован: {args.output_file}")
        
        # Дешифрование сообщения
        elif args.message:
            try:
                decrypted_message = decrypt_message(args.message, args.key_path)
                
                if args.output_file:
                    with open(args.output_file, 'w') as f:
                        f.write(decrypted_message)
                    print(f"Сообщение успешно дешифровано и сохранено в: {args.output_file}")
                else:
                    print(decrypted_message)
            except Exception as e:
                print(f"Ошибка при дешифровании сообщения: {str(e)}")


if __name__ == "__main__":
    main()