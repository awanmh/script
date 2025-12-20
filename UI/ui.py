import customtkinter as ctk
import sys
import os
from tkinter import messagebox

# --- SETUP PATH IMPORTS ---
# Menambahkan folder parent ke path agar bisa import package 'kriptografi'
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# --- IMPORTS DARI PACKAGE KRIPTOGRAFI ---
from kriptografi import hash_data
from kriptografi import derive_key                        # Dari PBKDF2
from kriptografi import rsa_pss                           # Dari RSA PSS (via alias di init)
from kriptografi import generate_keys, encrypt_message, decrypt_message  # Dari RSA Enkripsi
from kriptografi import Cipher, algorithms, modes, default_backend # Dari AES (via init)

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Konfigurasi Jendela Utama
        self.title("Tugas Cyber Security (Kriptografi)")
        self.geometry("800x600")
        ctk.set_appearance_mode("Dark")
        
        # --- STATE VARIABLES ---
        self.rsa_priv = None        # Untuk Enkripsi RSA
        self.rsa_pub = None         # Untuk Enkripsi RSA
        self.aes_key = None         # Untuk AES
        self.aes_iv = None          # Untuk AES
        self.pss_priv = None        # Untuk Tanda Tangan Digital
        self.pss_pub = None         # Untuk Tanda Tangan Digital
        self.last_signature = None  # Menyimpan tanda tangan terakhir

        # --- LAYOUT UTAMA (TABVIEW) ---
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)

        # Membuat 5 Tab
        self.tab_hash = self.tabview.add("Hashing")
        self.tab_pbkdf2 = self.tabview.add("Derivasi Kunci (PBKDF2)")
        self.tab_aes = self.tabview.add("AES (Simetris)")
        self.tab_rsa = self.tabview.add("RSA (Enkripsi)")
        self.tab_pss = self.tabview.add("RSA (Tanda Tangan)")

        # --- SETUP SETIAP TAB ---
        self.setup_hashing_tab()
        self.setup_pbkdf2_tab()     # Baru
        self.setup_aes_tab()
        self.setup_rsa_tab()
        self.setup_pss_tab()        # Baru

    # ==========================
    # 1. TAB HASHING
    # ==========================
    def setup_hashing_tab(self):
        ctk.CTkLabel(self.tab_hash, text="Hashing Data (SHA-256)", font=("Arial", 16, "bold")).pack(pady=10)
        self.hash_input = ctk.CTkEntry(self.tab_hash, width=400, placeholder_text="Masukkan teks...")
        self.hash_input.pack(pady=5)
        
        ctk.CTkButton(self.tab_hash, text="Generate Hash", command=self.process_hash).pack(pady=10)
        
        self.hash_output = ctk.CTkTextbox(self.tab_hash, height=80, width=500)
        self.hash_output.pack(pady=10)

    def process_hash(self):
        data = self.hash_input.get()
        if data:
            result = hash_data(data.encode())
            self.hash_output.delete("0.0", "end")
            self.hash_output.insert("0.0", result)

    # ==========================
    # 2. TAB PBKDF2 (Baru)
    # ==========================
    def setup_pbkdf2_tab(self):
        ctk.CTkLabel(self.tab_pbkdf2, text="Password to Key (PBKDF2)", font=("Arial", 16, "bold")).pack(pady=10)
        
        self.pbkdf2_pass = ctk.CTkEntry(self.tab_pbkdf2, width=400, placeholder_text="Masukkan Password Rahasia...", show="*")
        self.pbkdf2_pass.pack(pady=5)
        
        ctk.CTkButton(self.tab_pbkdf2, text="Derive Key (Buat Kunci)", command=self.process_pbkdf2).pack(pady=10)
        
        self.pbkdf2_output = ctk.CTkTextbox(self.tab_pbkdf2, height=100, width=500)
        self.pbkdf2_output.pack(pady=10)

    def process_pbkdf2(self):
        password = self.pbkdf2_pass.get()
        if not password:
            return
        
        # Generate Salt acak (simulasi input dari sistem)
        salt = os.urandom(16)
        
        # Panggil fungsi derive_key dari file Anda
        key = derive_key(password.encode(), salt)
        
        output = (
            f"Password Input: {password}\n"
            f"Generated Salt (Hex): {salt.hex()}\n"
            f"Derived Key (Hex): {key.hex()}\n"
            f"(Kunci ini aman digunakan untuk AES)"
        )
        self.pbkdf2_output.delete("0.0", "end")
        self.pbkdf2_output.insert("0.0", output)

    # ==========================
    # 3. TAB AES
    # ==========================
    def setup_aes_tab(self):
        ctk.CTkLabel(self.tab_aes, text="Enkripsi AES (Simetris)", font=("Arial", 16, "bold")).pack(pady=10)
        
        ctk.CTkButton(self.tab_aes, text="Generate Random Key & IV", fg_color="green", command=self.gen_aes_params).pack(pady=5)
        
        self.aes_input = ctk.CTkEntry(self.tab_aes, width=400, placeholder_text="Pesan rahasia...")
        self.aes_input.pack(pady=5)
        
        ctk.CTkButton(self.tab_aes, text="Encrypt & Decrypt Demo", command=self.process_aes).pack(pady=10)
        
        self.aes_output = ctk.CTkTextbox(self.tab_aes, height=120, width=500)
        self.aes_output.pack(pady=10)

    def gen_aes_params(self):
        self.aes_key = os.urandom(32)
        self.aes_iv = os.urandom(16)
        self.aes_output.delete("0.0", "end")
        self.aes_output.insert("0.0", f"Key Ready: {self.aes_key.hex()[:20]}...\nIV Ready: {self.aes_iv.hex()}...")

    def process_aes(self):
        # PERBAIKAN: Cek secara eksplisit apakah Key ATAU IV bernilai None
        if self.aes_key is None or self.aes_iv is None:
            messagebox.showwarning("Error", "Klik Generate Key dulu!")
            return
        
        # Karena sudah dicek di atas, editor sekarang tahu variabel ini pasti 'bytes'
        plaintext = self.aes_input.get().encode()
        
        # Implementasi logika AES
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CFB(self.aes_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        
        self.aes_output.delete("0.0", "end")
        self.aes_output.insert("0.0", f"Ciphertext (Hex): {ciphertext.hex()}\nDecrypted Text: {decrypted.decode()}")

    # ==========================
    # 4. TAB RSA (ENKRIPSI)
    # ==========================
    def setup_rsa_tab(self):
        ctk.CTkLabel(self.tab_rsa, text="Enkripsi RSA (Asimetris)", font=("Arial", 16, "bold")).pack(pady=10)
        
        ctk.CTkButton(self.tab_rsa, text="Buat Kunci RSA (Keypair)", fg_color="green", command=self.gen_rsa_keys).pack(pady=5)
        
        self.rsa_input = ctk.CTkEntry(self.tab_rsa, width=400, placeholder_text="Pesan untuk dienkripsi...")
        self.rsa_input.pack(pady=5)
        
        frame = ctk.CTkFrame(self.tab_rsa)
        frame.pack(pady=5)
        ctk.CTkButton(frame, text="Encrypt", command=self.rsa_encrypt).pack(side="left", padx=5)
        ctk.CTkButton(frame, text="Decrypt", command=self.rsa_decrypt).pack(side="left", padx=5)
        
        self.rsa_output = ctk.CTkTextbox(self.tab_rsa, height=100, width=500)
        self.rsa_output.pack(pady=10)
        self.last_rsa_cipher = None

    def gen_rsa_keys(self):
        self.rsa_priv, self.rsa_pub = generate_keys()
        messagebox.showinfo("Info", "Kunci RSA untuk Enkripsi berhasil dibuat!")

    def rsa_encrypt(self):
        if not self.rsa_pub: return
        self.last_rsa_cipher = encrypt_message(self.rsa_pub, self.rsa_input.get().encode())
        self.rsa_output.delete("0.0", "end")
        self.rsa_output.insert("0.0", f"Encrypted (Hex):\n{self.last_rsa_cipher.hex()}")

    def rsa_decrypt(self):
        if not self.rsa_priv or not self.last_rsa_cipher: return
        try:
            plain = decrypt_message(self.rsa_priv, self.last_rsa_cipher)
            self.rsa_output.delete("0.0", "end")
            self.rsa_output.insert("0.0", f"Decrypted:\n{plain.decode()}")
        except:
            messagebox.showerror("Error", "Gagal dekripsi!")

    # ==========================
    # 5. TAB RSA PSS (SIGNATURE) - Baru
    # ==========================
    def setup_pss_tab(self):
        ctk.CTkLabel(self.tab_pss, text="Digital Signature (RSA PSS)", font=("Arial", 16, "bold")).pack(pady=10)
        
        # Tombol generate key khusus untuk signing
        ctk.CTkButton(self.tab_pss, text="Buat Kunci Signing", fg_color="green", command=self.gen_pss_keys).pack(pady=5)
        
        self.pss_input = ctk.CTkEntry(self.tab_pss, width=400, placeholder_text="Dokumen/Pesan untuk ditanda tangani...")
        self.pss_input.pack(pady=5)
        
        frame = ctk.CTkFrame(self.tab_pss)
        frame.pack(pady=5)
        ctk.CTkButton(frame, text="Sign Message", command=self.process_sign).pack(side="left", padx=5)
        ctk.CTkButton(frame, text="Verify Signature", command=self.process_verify).pack(side="left", padx=5)
        
        self.pss_output = ctk.CTkTextbox(self.tab_pss, height=100, width=500)
        self.pss_output.pack(pady=10)

    def gen_pss_keys(self):
        # Menggunakan fungsi generate_keys dari file cryptographyRSA_PSS.py (via alias rsa_pss)
        self.pss_priv, self.pss_pub = rsa_pss.generate_keys()
        messagebox.showinfo("Info", "Kunci Signing berhasil dibuat!")
        self.pss_output.insert("0.0", "Kunci Signing Siap.\n")

    def process_sign(self):
        if not self.pss_priv:
            messagebox.showwarning("Error", "Buat kunci signing dulu!")
            return
            
        msg = self.pss_input.get().encode()
        # Sign pesan
        self.last_signature = rsa_pss.sign_message(self.pss_priv, msg)
        
        self.pss_output.delete("0.0", "end")
        self.pss_output.insert("0.0", f"Signature (Hex):\n{self.last_signature.hex()}\n\n(Tanda tangan ini unik untuk pesan di atas)")

    def process_verify(self):
        if not self.pss_pub or not self.last_signature:
            messagebox.showwarning("Error", "Belum ada pesan yang ditandatangani.")
            return
            
        msg = self.pss_input.get().encode()
        try:
            # Verify pesan
            rsa_pss.verify_signature(self.pss_pub, self.last_signature, msg)
            self.pss_output.delete("0.0", "end")
            self.pss_output.insert("0.0", "VERIFIKASI SUKSES!\n\nPesan Valid dan berasal dari pemegang Private Key.")
        except Exception as e:
            self.pss_output.delete("0.0", "end")
            self.pss_output.insert("0.0", f"VERIFIKASI GAGAL!\nPesan mungkin telah dimanipulasi atau bukan dari pengirim asli.\nError: {e}")

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()