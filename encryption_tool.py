#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة التشفير التفاعلية
Interactive Encryption Tool
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import base64
import binascii
import urllib.parse
from custom_crypto import CustomCrypto


class EncryptionTool:
    """أداة التشفير التفاعلية"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 أداة التشفير التفاعلية")
        self.root.geometry("800x600")
        self.root.configure(bg='#2b2b2b')
        
        # إنشاء محرك التشفير المخصص
        self.custom_crypto = CustomCrypto()
        
        self.setup_ui()
    
    def setup_ui(self):
        """إعداد الواجهة"""
        # العنوان
        title_label = tk.Label(
            self.root,
            text="🔐 أداة التشفير التفاعلية",
            font=('Arial', 16, 'bold'),
            fg='white',
            bg='#2b2b2b'
        )
        title_label.pack(pady=10)
        
        # الإطار الرئيسي
        main_frame = tk.Frame(self.root, bg='#2b2b2b')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # الجانب الأيسر - النص الأصلي
        left_frame = tk.LabelFrame(
            main_frame,
            text="النص الأصلي",
            fg='white',
            bg='#2b2b2b',
            font=('Arial', 10, 'bold')
        )
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,5))
        
        self.original_text = scrolledtext.ScrolledText(
            left_frame,
            height=15,
            bg='#1e1e1e',
            fg='white',
            insertbackground='white',
            font=('Consolas', 9)
        )
        self.original_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # الجانب الأيمن - النص المشفر
        right_frame = tk.LabelFrame(
            main_frame,
            text="النص المشفر",
            fg='white',
            bg='#2b2b2b',
            font=('Arial', 10, 'bold')
        )
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5,0))
        
        self.encrypted_text = scrolledtext.ScrolledText(
            right_frame,
            height=15,
            bg='#1e1e1e',
            fg='white',
            insertbackground='white',
            font=('Consolas', 9)
        )
        self.encrypted_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # إعدادات التشفير
        settings_frame = tk.Frame(self.root, bg='#2b2b2b')
        settings_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # نوع التشفير
        tk.Label(settings_frame, text="نوع التشفير:", fg='white', bg='#2b2b2b').pack(side=tk.LEFT)
        self.encrypt_method_var = tk.StringVar(value="base64")
        encrypt_method_combo = ttk.Combobox(
            settings_frame,
            textvariable=self.encrypt_method_var,
            values=["base64", "hex", "url", "caesar", "rot13", "custom_xor", 
                   "multi_caesar", "substitution", "transposition", 
                   "vigenere_advanced", "spiral", "zigzag", "book_cipher"],
            state="readonly",
            width=15
        )
        encrypt_method_combo.pack(side=tk.LEFT, padx=5)
        
        # المفتاح
        tk.Label(settings_frame, text="المفتاح:", fg='white', bg='#2b2b2b').pack(side=tk.LEFT, padx=(20,0))
        self.key_var = tk.StringVar()
        key_entry = tk.Entry(settings_frame, textvariable=self.key_var, width=20)
        key_entry.pack(side=tk.LEFT, padx=5)
        
        # الأزرار
        button_frame = tk.Frame(self.root, bg='#2b2b2b')
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        encrypt_button = tk.Button(
            button_frame,
            text="🔐 تشفير",
            command=self.encrypt_text,
            bg='#4CAF50',
            fg='white',
            font=('Arial', 10, 'bold')
        )
        encrypt_button.pack(side=tk.LEFT, padx=5)
        
        decrypt_button = tk.Button(
            button_frame,
            text="🔓 فك التشفير",
            command=self.decrypt_text,
            bg='#2196F3',
            fg='white',
            font=('Arial', 10, 'bold')
        )
        decrypt_button.pack(side=tk.LEFT, padx=5)
        
        clear_button = tk.Button(
            button_frame,
            text="🗑️ مسح",
            command=self.clear_all,
            bg='#FF9800',
            fg='white',
            font=('Arial', 10, 'bold')
        )
        clear_button.pack(side=tk.LEFT, padx=5)
        
        copy_button = tk.Button(
            button_frame,
            text="📋 نسخ المشفر",
            command=self.copy_encrypted,
            bg='#9C27B0',
            fg='white',
            font=('Arial', 10, 'bold')
        )
        copy_button.pack(side=tk.LEFT, padx=5)
        
        save_button = tk.Button(
            button_frame,
            text="💾 حفظ",
            command=self.save_to_file,
            bg='#607D8B',
            fg='white',
            font=('Arial', 10, 'bold')
        )
        save_button.pack(side=tk.LEFT, padx=5)
        
        # أزرار النماذج السريعة
        samples_frame = tk.Frame(self.root, bg='#2b2b2b')
        samples_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(samples_frame, text="نماذج سريعة:", fg='white', bg='#2b2b2b').pack(side=tk.LEFT)
        
        samples = [
            ("رسالة بسيطة", "Hello World!"),
            ("بيانات اعتماد", "username=admin&password=secret123"),
            ("رسالة طويلة", "This is a longer message for testing encryption algorithms with multiple words and sentences."),
            ("أرقام", "1234567890"),
            ("رموز خاصة", "!@#$%^&*()_+-=[]{}|;:,.<>?")
        ]
        
        for name, text in samples:
            btn = tk.Button(
                samples_frame,
                text=name,
                command=lambda t=text: self.load_sample(t),
                bg='#795548',
                fg='white',
                font=('Arial', 8)
            )
            btn.pack(side=tk.LEFT, padx=2)
        
        # شريط الحالة
        self.status_bar = tk.Label(
            self.root,
            text="جاهز للتشفير",
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg='#1e1e1e',
            fg='white'
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def load_sample(self, text):
        """تحميل نموذج نص"""
        self.original_text.delete(1.0, tk.END)
        self.original_text.insert(1.0, text)
        self.update_status(f"تم تحميل النموذج: {text[:20]}...")
    
    def encrypt_text(self):
        """تشفير النص"""
        text = self.original_text.get(1.0, tk.END).strip()
        if not text:
            messagebox.showwarning("تحذير", "يرجى إدخال نص للتشفير")
            return
        
        method = self.encrypt_method_var.get()
        key = self.key_var.get() if self.key_var.get() else None
        
        self.encrypted_text.delete(1.0, tk.END)
        
        try:
            if method == "base64":
                result = base64.b64encode(text.encode()).decode()
            elif method == "hex":
                result = text.encode().hex()
            elif method == "url":
                result = urllib.parse.quote(text)
            elif method == "caesar":
                shift = int(key) if key and key.isdigit() else 3
                result = self.caesar_encrypt(text, shift)
            elif method == "rot13":
                result = self.caesar_encrypt(text, 13)
            elif method == "custom_xor":
                result = self.custom_crypto.custom_xor_encrypt(text, key)
            elif method == "multi_caesar":
                shifts = [int(x) for x in key.split(',')] if key else [3, 7, 11, 13, 17]
                result = self.custom_crypto.multi_caesar_encrypt(text, shifts)
            elif method == "substitution":
                result = self.custom_crypto.substitution_encrypt(text)
            elif method == "transposition":
                result = self.custom_crypto.transposition_encrypt(text, key)
            elif method == "vigenere_advanced":
                result = self.custom_crypto.vigenere_advanced_encrypt(text, key)
            elif method == "spiral":
                size = int(key) if key and key.isdigit() else None
                result = self.custom_crypto.spiral_encrypt(text, size)
            elif method == "zigzag":
                rails = int(key) if key and key.isdigit() else 3
                result = self.custom_crypto.zigzag_encrypt(text, rails)
            elif method == "book_cipher":
                result = self.custom_crypto.book_cipher_encrypt(text)
            else:
                result = "نوع التشفير غير مدعوم"
            
            self.encrypted_text.insert(1.0, result)
            self.update_status(f"تم التشفير باستخدام {method}")
            
        except Exception as e:
            messagebox.showerror("خطأ", f"فشل في التشفير:\n{str(e)}")
            self.update_status("فشل في التشفير")
    
    def decrypt_text(self):
        """فك تشفير النص"""
        text = self.encrypted_text.get(1.0, tk.END).strip()
        if not text:
            messagebox.showwarning("تحذير", "يرجى إدخال نص مشفر لفك التشفير")
            return
        
        method = self.encrypt_method_var.get()
        key = self.key_var.get() if self.key_var.get() else None
        
        self.original_text.delete(1.0, tk.END)
        
        try:
            if method == "base64":
                result = base64.b64decode(text).decode('utf-8', errors='ignore')
            elif method == "hex":
                result = bytes.fromhex(text).decode('utf-8', errors='ignore')
            elif method == "url":
                result = urllib.parse.unquote(text)
            elif method == "caesar":
                shift = int(key) if key and key.isdigit() else 3
                result = self.caesar_decrypt(text, shift)
            elif method == "rot13":
                result = self.caesar_decrypt(text, 13)
            elif method == "custom_xor":
                result = self.custom_crypto.custom_xor_decrypt(text, key)
            elif method == "multi_caesar":
                shifts = [int(x) for x in key.split(',')] if key else [3, 7, 11, 13, 17]
                result = self.custom_crypto.multi_caesar_decrypt(text, shifts)
            elif method == "substitution":
                result = self.custom_crypto.substitution_decrypt(text)
            elif method == "transposition":
                result = self.custom_crypto.transposition_decrypt(text, key)
            elif method == "vigenere_advanced":
                result = self.custom_crypto.vigenere_advanced_decrypt(text, key)
            elif method == "spiral":
                size = int(key) if key and key.isdigit() else None
                result = self.custom_crypto.spiral_decrypt(text, size)
            elif method == "zigzag":
                rails = int(key) if key and key.isdigit() else 3
                result = self.custom_crypto.zigzag_decrypt(text, rails)
            elif method == "book_cipher":
                result = self.custom_crypto.book_cipher_decrypt(text)
            else:
                result = "نوع التشفير غير مدعوم"
            
            self.original_text.insert(1.0, result)
            self.update_status(f"تم فك التشفير باستخدام {method}")
            
        except Exception as e:
            messagebox.showerror("خطأ", f"فشل في فك التشفير:\n{str(e)}")
            self.update_status("فشل في فك التشفير")
    
    def caesar_encrypt(self, text, shift):
        """تشفير قيصر"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def caesar_decrypt(self, text, shift):
        """فك تشفير قيصر"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def clear_all(self):
        """مسح جميع النصوص"""
        self.original_text.delete(1.0, tk.END)
        self.encrypted_text.delete(1.0, tk.END)
        self.key_var.set("")
        self.update_status("تم مسح جميع النصوص")
    
    def copy_encrypted(self):
        """نسخ النص المشفر"""
        encrypted = self.encrypted_text.get(1.0, tk.END).strip()
        if encrypted:
            self.root.clipboard_clear()
            self.root.clipboard_append(encrypted)
            self.update_status("تم نسخ النص المشفر")
        else:
            messagebox.showwarning("تحذير", "لا يوجد نص مشفر للنسخ")
    
    def save_to_file(self):
        """حفظ النتائج في ملف"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("🔐 نتائج التشفير\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"نوع التشفير: {self.encrypt_method_var.get()}\n")
                    f.write(f"المفتاح: {self.key_var.get()}\n\n")
                    f.write("النص الأصلي:\n")
                    f.write("-" * 20 + "\n")
                    f.write(self.original_text.get(1.0, tk.END))
                    f.write("\n\nالنص المشفر:\n")
                    f.write("-" * 20 + "\n")
                    f.write(self.encrypted_text.get(1.0, tk.END))
                
                messagebox.showinfo("نجح", f"تم حفظ الملف:\n{filename}")
                self.update_status(f"تم حفظ الملف: {filename}")
                
            except Exception as e:
                messagebox.showerror("خطأ", f"فشل في حفظ الملف:\n{str(e)}")
    
    def update_status(self, message):
        """تحديث شريط الحالة"""
        self.status_bar.config(text=message)
    
    def run(self):
        """تشغيل الأداة"""
        self.root.mainloop()


def main():
    """الدالة الرئيسية"""
    app = EncryptionTool()
    app.run()


if __name__ == "__main__":
    main()