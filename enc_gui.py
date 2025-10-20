#!/usr/bin/env python3
"""
GUI версия программы для шифрования и дешифрования данных с использованием асимметричных ключей.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Программа шифрования/дешифрования")
        self.root.geometry("800x600")
        
        # Создаем ноутбук для вкладок
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Создаем вкладки
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.decrypt_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.encrypt_frame, text="Шифрование")
        self.notebook.add(self.decrypt_frame, text="Дешифрование")
        
        # Инициализируем вкладки
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
    
    def setup_encrypt_tab(self):
        """Настройка вкладки шифрования"""
        # Выбор публичного ключа
        ttk.Label(self.encrypt_frame, text="Публичный ключ:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.public_key_var = tk.StringVar()
        self.public_key_combo = ttk.Combobox(self.encrypt_frame, textvariable=self.public_key_var, state="readonly", width=50)
        self.public_key_combo.grid(row=0, column=1, padx=5, pady=5)
        
        self.refresh_public_keys_btn = ttk.Button(self.encrypt_frame, text="Обновить список", command=self.refresh_public_keys)
        self.refresh_public_keys_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Текстовое поле для ввода сообщения
        ttk.Label(self.encrypt_frame, text="Сообщение:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.encrypt_text = scrolledtext.ScrolledText(self.encrypt_frame, height=6, width=70)
        self.encrypt_text.grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        
        # Кнопка выбора файла
        self.encrypt_file_btn = ttk.Button(self.encrypt_frame, text="Выбрать файл", command=self.select_encrypt_file)
        self.encrypt_file_btn.grid(row=3, column=0, padx=5, pady=5)
        
        self.encrypt_file_path = tk.StringVar()
        self.encrypt_file_label = ttk.Label(self.encrypt_frame, text="Файл не выбран", width=50)
        self.encrypt_file_label.grid(row=3, column=1, padx=5, pady=5)
        
        # Кнопка шифрования
        self.encrypt_btn = ttk.Button(self.encrypt_frame, text="Зашифровать", command=self.encrypt_action)
        self.encrypt_btn.grid(row=3, column=2, padx=5, pady=5)
        
        # Кнопка генерации ключей
        self.generate_keys_btn = ttk.Button(self.encrypt_frame, text="Сгенерировать ключи", command=self.generate_keys)
        self.generate_keys_btn.grid(row=4, column=0, columnspan=3, pady=10)
        
        # Инициализация списка ключей
        self.refresh_public_keys()
    
    def setup_decrypt_tab(self):
        """Настройка вкладки дешифрования"""
        # Выбор приватного ключа
        ttk.Label(self.decrypt_frame, text="Приватный ключ:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.private_key_var = tk.StringVar()
        self.private_key_combo = ttk.Combobox(self.decrypt_frame, textvariable=self.private_key_var, state="readonly", width=50)
        self.private_key_combo.grid(row=0, column=1, padx=5, pady=5)
        
        self.refresh_private_keys_btn = ttk.Button(self.decrypt_frame, text="Обновить список", command=self.refresh_private_keys)
        self.refresh_private_keys_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Текстовое поле для ввода сообщения
        ttk.Label(self.decrypt_frame, text="Сообщение:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.decrypt_text = scrolledtext.ScrolledText(self.decrypt_frame, height=6, width=70)
        self.decrypt_text.grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        
        # Кнопка выбора файла
        self.decrypt_file_btn = ttk.Button(self.decrypt_frame, text="Выбрать файл", command=self.select_decrypt_file)
        self.decrypt_file_btn.grid(row=3, column=0, padx=5, pady=5)
        
        self.decrypt_file_path = tk.StringVar()
        self.decrypt_file_label = ttk.Label(self.decrypt_frame, text="Файл не выбран", width=50)
        self.decrypt_file_label.grid(row=3, column=1, padx=5, pady=5)
        
        # Кнопка дешифрования
        self.decrypt_btn = ttk.Button(self.decrypt_frame, text="Дешифровать", command=self.decrypt_action)
        self.decrypt_btn.grid(row=3, column=2, padx=5, pady=5)
        
        # Инициализация списка ключей
        self.refresh_private_keys()
    
    def refresh_public_keys(self):
        """Обновление списка публичных ключей"""
        # Получаем директорию, где находится скрипт
        script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
        pubkeys_dir = os.path.join(script_dir, "pubkeys")
        if not os.path.exists(pubkeys_dir):
            os.makedirs(pubkeys_dir)
        
        public_keys = []
        for file in os.listdir(pubkeys_dir):
            if file.endswith(".pem"):
                # Сохраняем как кортеж (отображаемое имя, полный путь)
                full_path = os.path.join(pubkeys_dir, file)
                public_keys.append((file, full_path))
        
        # Отображаем только имена файлов
        display_names = [item[0] for item in public_keys]
        self.public_key_combo['values'] = display_names
        self.public_key_full_paths = {item[0]: item[1] for item in public_keys}  # Словарь для получения полного пути по имени
        if display_names:
            self.public_key_combo.set(display_names[0])
        else:
            self.public_key_combo.set("")
    
    def refresh_private_keys(self):
        """Обновление списка приватных ключей"""
        # Получаем директорию, где находится скрипт
        script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
        privatekeys_dir = os.path.join(script_dir, "privatekeys")
        if not os.path.exists(privatekeys_dir):
            os.makedirs(privatekeys_dir)
        
        private_keys = []
        for file in os.listdir(privatekeys_dir):
            if file.endswith(".pem"):
                # Сохраняем как кортеж (отображаемое имя, полный путь)
                full_path = os.path.join(privatekeys_dir, file)
                private_keys.append((file, full_path))
        
        # Отображаем только имена файлов
        display_names = [item[0] for item in private_keys]
        self.private_key_combo['values'] = display_names
        self.private_key_full_paths = {item[0]: item[1] for item in private_keys}  # Словарь для получения полного пути по имени
        if display_names:
            self.private_key_combo.set(display_names[0])
        else:
            self.private_key_combo.set("")
    
    def select_encrypt_file(self):
        """Выбор файла для шифрования"""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.encrypt_file_path.set(file_path)
            self.encrypt_file_label.config(text=os.path.basename(file_path))
    
    def select_decrypt_file(self):
        """Выбор файла для дешифрования"""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.decrypt_file_path.set(file_path)
            self.decrypt_file_label.config(text=os.path.basename(file_path))
    
    def generate_keys(self):
        """Генерация новой пары ключей"""
        try:
            # Генерируем пару ключей
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            
            # Получаем директорию, где находится скрипт
            script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
            
            # Создаем директории, если не существуют
            privatekeys_dir = os.path.join(script_dir, 'privatekeys')
            pubkeys_dir = os.path.join(script_dir, 'pubkeys')
            os.makedirs(privatekeys_dir, exist_ok=True)
            os.makedirs(pubkeys_dir, exist_ok=True)
            
            # Сохраняем приватный ключ в директорию privatekeys
            private_key_filename = f"private_key_{secrets.token_hex(4)}.pem"
            private_key_path = os.path.join(privatekeys_dir, private_key_filename)
            
            with open(private_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Предлагаем пользователю сохранить публичный ключ
            public_key_filename = filedialog.asksaveasfilename(
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
                initialfile="public_key.pem",
                title="Сохранить публичный ключ"
            )
            
            if public_key_filename:
                with open(public_key_filename, 'wb') as f:
                    f.write(public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                
                messagebox.showinfo("Успех", f"Ключи успешно сгенерированы:\nПриватный: {private_key_path}\nПубличный: {public_key_filename}")
                
                # Обновляем списки ключей
                self.refresh_public_keys()
                self.refresh_private_keys()
            else:
                # Если пользователь отменил сохранение публичного ключа, удаляем приватный
                os.remove(private_key_path)
                messagebox.showwarning("Предупреждение", "Генерация ключей отменена. Публичный ключ не был сохранен.")
        
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при генерации ключей: {str(e)}")
    
    def encrypt_action(self):
        """Выполнение шифрования"""
        try:
            # Проверяем выбран ли ключ
            public_key_display_name = self.public_key_var.get()
            if not public_key_display_name:
                messagebox.showerror("Ошибка", "Пожалуйста, выберите публичный ключ")
                return
            
            # Получаем полный путь к ключу по отображаемому имени
            public_key_path = self.public_key_full_paths.get(public_key_display_name, public_key_display_name)
            
            # Загружаем публичный ключ
            # Если путь к ключу не является абсолютным, предполагаем что он относительный и добавляем путь к скрипту
            if not os.path.isabs(public_key_path):
                script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
                public_key_path = os.path.join(script_dir, public_key_path)
                
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            
            # Определяем, что шифровать: текст или файл
            text_content = self.encrypt_text.get("1.0", tk.END).strip()
            file_path = self.encrypt_file_path.get()
            
            if text_content and file_path:
                messagebox.showerror("Ошибка", "Выберите либо текст, либо файл для шифрования")
                return
            
            if not text_content and not file_path:
                messagebox.showerror("Ошибка", "Выберите текст или файл для шифрования")
                return
            
            if text_content:
                # Шифруем текст
                encrypted_data = self.encrypt_data(public_key, text_content.encode('utf-8'))
                encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
                
                # Открываем новое окно с результатом
                result_window = tk.Toplevel(self.root)
                result_window.title("Результат шифрования")
                result_window.geometry("600x400")
                
                result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
                result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                result_text.insert(tk.END, encrypted_b64)
                
                # Выделяем весь текст для удобства копирования
                result_text.tag_add(tk.SEL, "1.0", tk.END)  # Выделяем весь текст для удобства копирования
                result_text.tag_config(tk.SEL, background="lightblue")  # Устанавливаем цвет выделения
                result_text.mark_set(tk.INSERT, "1.0")  # Устанавливаем курсор в начало
                
                # Блокируем вставку текста, чтобы предотвратить редактирование
                def limit_input(event):
                    # Разрешаем только копирование (Ctrl+C, Ctrl+Insert), вырезание (Ctrl+X) и другие системные команды
                    if event.state & 0x4:  # Ctrl is pressed
                        if event.keysym in ['c', 'C', 'Insert', 'x', 'X']:
                            return None  # Allow copying, cutting
                    if event.keysym in ['Up', 'Down', 'Left', 'Right', 'Home', 'End', 'Prior', 'Next']:  # Navigation keys
                        return None
                    if event.keysym in ['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12']:  # Function keys
                        return None
                    return "break"  # Block all other input
                
                result_text.bind("<KeyPress>", limit_input)
                
                # Привязываем обработчик для разрешения копирования (Ctrl+C)
                def copy_text(event):
                    try:
                        result_text.clipboard_clear()
                        result_text.clipboard_append(result_text.get(tk.SEL_FIRST, tk.SEL_LAST))
                    except tk.TclError:
                        # Если ничего не выделено
                        result_text.clipboard_clear()
                        result_text.clipboard_append(result_text.get("1.0", tk.END))
                    return "break"
                
                result_text.bind("<Control-c>", copy_text)
                result_text.bind("<Control-C>", copy_text)
                
                # Кнопка сохранения результата
                def save_result():
                    save_path = filedialog.asksaveasfilename(
                        defaultextension=".txt",
                        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                    )
                    if save_path:
                        with open(save_path, 'w') as f:
                            f.write(encrypted_b64)
                        messagebox.showinfo("Успех", f"Результат сохранен в {save_path}")
                
                save_btn = ttk.Button(result_window, text="Сохранить результат", command=save_result)
                save_btn.pack(pady=5)
            
            elif file_path:
                # Шифруем файл
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                
                encrypted_data = self.encrypt_data(public_key, file_data)
                
                # Предлагаем сохранить зашифрованный файл
                output_path = filedialog.asksaveasfilename(
                    defaultextension=".enc",
                    filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
                    title="Сохранить зашифрованный файл"
                )
                
                if output_path:
                    with open(output_path, 'wb') as f:
                        f.write(encrypted_data)
                    messagebox.showinfo("Успех", f"Файл успешно зашифрован и сохранен в {output_path}")
        
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании: {str(e)}")
    
    def decrypt_action(self):
        """Выполнение дешифрования"""
        try:
            # Проверяем выбран ли ключ
            private_key_display_name = self.private_key_var.get()
            if not private_key_display_name:
                messagebox.showerror("Ошибка", "Пожалуйста, выберите приватный ключ")
                return
            
            # Получаем полный путь к ключу по отображаемому имени
            private_key_path = self.private_key_full_paths.get(private_key_display_name, private_key_display_name)
            
            # Загружаем приватный ключ
            # Если путь к ключу не является абсолютным, предполагаем что он относительный и добавляем путь к скрипту
            if not os.path.isabs(private_key_path):
                script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
                private_key_path = os.path.join(script_dir, private_key_path)
                
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            # Определяем, что дешифровать: текст или файл
            text_content = self.decrypt_text.get("1.0", tk.END).strip()
            file_path = self.decrypt_file_path.get()
            
            if text_content and file_path:
                messagebox.showerror("Ошибка", "Выберите либо текст, либо файл для дешифрования")
                return
            
            if not text_content and not file_path:
                messagebox.showerror("Ошибка", "Выберите текст или файл для дешифрования")
                return
            
            if text_content:
                # Дешифруем текст (ожидаем base64-закодированный шифротекст)
                try:
                    encrypted_data = base64.b64decode(text_content.encode('utf-8'))
                except Exception:
                    messagebox.showerror("Ошибка", "Текст не является корректно закодированным base64")
                    return
                
                decrypted_data = self.decrypt_data(private_key, encrypted_data)
                decrypted_text = decrypted_data.decode('utf-8')
                
                # Открываем новое окно с результатом
                result_window = tk.Toplevel(self.root)
                result_window.title("Результат дешифрования")
                result_window.geometry("600x400")
                
                result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
                result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                result_text.insert(tk.END, decrypted_text)
                
                # Выделяем весь текст для удобства копирования
                result_text.tag_add(tk.SEL, "1.0", tk.END)  # Выделяем весь текст для удобства копирования
                result_text.tag_config(tk.SEL, background="lightblue")  # Устанавливаем цвет выделения
                result_text.mark_set(tk.INSERT, "1.0")  # Устанавливаем курсор в начало
                
                # Блокируем вставку текста, чтобы предотвратить редактирование
                def limit_input(event):
                    # Разрешаем только копирование (Ctrl+C, Ctrl+Insert), вырезание (Ctrl+X) и другие системные команды
                    if event.state & 0x4:  # Ctrl is pressed
                        if event.keysym in ['c', 'C', 'Insert', 'x', 'X']:
                            return None  # Allow copying, cutting
                    if event.keysym in ['Up', 'Down', 'Left', 'Right', 'Home', 'End', 'Prior', 'Next']:  # Navigation keys
                        return None
                    if event.keysym in ['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12']:  # Function keys
                        return None
                    return "break"  # Block all other input
                
                result_text.bind("<KeyPress>", limit_input)
                
                # Привязываем обработчик для разрешения копирования (Ctrl+C)
                def copy_text(event):
                    try:
                        result_text.clipboard_clear()
                        result_text.clipboard_append(result_text.get(tk.SEL_FIRST, tk.SEL_LAST))
                    except tk.TclError:
                        # Если ничего не выделено
                        result_text.clipboard_clear()
                        result_text.clipboard_append(result_text.get("1.0", tk.END))
                    return "break"
                
                result_text.bind("<Control-c>", copy_text)
                result_text.bind("<Control-C>", copy_text)
                
                # Кнопка сохранения результата
                def save_result():
                    save_path = filedialog.asksaveasfilename(
                        defaultextension=".txt",
                        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                    )
                    if save_path:
                        with open(save_path, 'w') as f:
                            f.write(decrypted_text)
                        messagebox.showinfo("Успех", f"Результат сохранен в {save_path}")
                
                save_btn = ttk.Button(result_window, text="Сохранить результат", command=save_result)
                save_btn.pack(pady=5)
            
            elif file_path:
                # Дешифруем файл
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = self.decrypt_data(private_key, encrypted_data)
                
                # Предлагаем сохранить расшифрованный файл
                output_path = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                    title="Сохранить расшифрованный файл"
                )
                
                if output_path:
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                    messagebox.showinfo("Успех", f"Файл успешно дешифрован и сохранен в {output_path}")
        
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при дешифровании: {str(e)}")
    
    def encrypt_data(self, public_key, data):
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
        padded_data = self._pad_data(data)
        
        # Шифруем данные
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Комбинируем зашифрованный симметричный ключ, IV и зашифрованные данные
        result = encrypted_symmetric_key + iv + encrypted_data
        
        return result
    
    def decrypt_data(self, private_key, encrypted_data):
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
        original_data = self._unpad_data(padded_data)
        
        return original_data
    
    def _pad_data(self, data):
        """
        Добавляет padding к данным для соответствия размера блока AES (16 байт)
        """
        block_size = 16
        padding_len = block_size - (len(data) % block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding
    
    def _unpad_data(self, padded_data):
        """
        Убирает padding из данных
        """
        padding_len = padded_data[-1]
        return padded_data[:-padding_len]


def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()