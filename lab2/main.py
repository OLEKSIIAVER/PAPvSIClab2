import os
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.backends import default_backend


# Функція для генерації ключа та IV
def generate_key_and_iv(password: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 байти = 256 біт для AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    iv = os.urandom(16)  # 16 байт = 128 біт для AES
    return key, iv

# Функція для шифрування файлу
def encrypt_file(input_file: str, output_file: str, password: bytes):
    salt = os.urandom(16)
    key, iv = generate_key_and_iv(password, salt)

    with open(input_file, 'rb') as f:
        data = f.read()

    # Додавання доповнення
    padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Шифрування даних
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Обчислення MAC
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    mac = h.finalize()

    # Збереження даних
    with open(output_file, 'wb') as f:
        f.write(salt + iv + mac + encrypted_data)

# Функція для дешифрування файлу
def decrypt_file(input_file: str, output_file: str, password: bytes):
    try:
        with open(input_file, 'rb') as f:
            content = f.read()
            if len(content) < 64:  # Перевірка на достатню довжину
                raise ValueError("Input file is too short to contain valid data.")

            print("Content length:", len(content))  # Додано для відлагодження
            salt = content[:16]
            iv = content[16:32]
            mac = content[32:64]
            encrypted_data = content[64:]

            print("Salt:", salt)
            print("IV:", iv)
            print("MAC:", mac)
            print("Encrypted data length:", len(encrypted_data))

        key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        ).derive(password)

        # Перевірка MAC
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_data)
        h.verify(mac)

        # Дешифрування
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Видалення доповнення
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        with open(output_file, 'wb') as f:
            f.write(data)
            print(f"Decrypted data written to {output_file}, size: {len(data)} bytes")  # Додано для відлагодження

    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        messagebox.showerror("Error", f"Decryption failed: {e}")


# Генерація пари ключів RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private, pem_public

# Шифрування даних з використанням RSA
def rsa_encrypt(data: bytes, public_key: bytes):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    encrypted_data = public_key.encrypt(
        data,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

# Підписування даних
def sign_data(data: bytes, private_key: bytes):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    signature = private_key.sign(
        data,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Перевірка підпису
def verify_signature(data: bytes, signature: bytes, public_key: bytes):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    public_key.verify(
        signature,
        data,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Функція для вибору файлу
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        input_file_entry.delete(0, 'end')
        input_file_entry.insert(0, file_path)

# Функція для шифрування файлу
def encrypt_action():
    password = password_entry.get().encode()
    input_file = input_file_entry.get()
    if not input_file or not password:
        messagebox.showerror("Error", "Please enter a password and select an input file.")
        return
    encrypted_file = "encrypted.bin"
    encrypt_file(input_file, encrypted_file, password)
    messagebox.showinfo("Success", "File encrypted successfully!")

# Функція для дешифрування файлу
def decrypt_action():
    password = password_entry.get().encode()
    input_file = "encrypted.bin"
    decrypted_file = "decrypted.txt"
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return
    decrypt_file(input_file, decrypted_file, password)
    messagebox.showinfo("Success", "File decrypted successfully!")

# Графічний інтерфейс
root = Tk()
root.title("AES Encryption/Decryption")

# Поле для вводу пароля
Label(root, text="Password:").grid(row=0, column=0)
password_entry = Entry(root, show='*')
password_entry.grid(row=0, column=1)

# Кнопка для вибору файлу
Label(root, text="Input File:").grid(row=1, column=0)
input_file_entry = Entry(root)
input_file_entry.grid(row=1, column=1)
Button(root, text="Browse", command=select_file).grid(row=1, column=2)

# Кнопка для шифрування
Button(root, text="Encrypt", command=encrypt_action).grid(row=2, column=0, columnspan=3)

# Кнопка для дешифрування
Button(root, text="Decrypt", command=decrypt_action).grid(row=3, column=0, columnspan=3)

# Запуск програми
root.mainloop()
