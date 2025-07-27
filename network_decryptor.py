#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة فك تشفير الرسائل من الشبكة
Network Message Decryptor Tool
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import threading
import queue
import base64
import hashlib
import json
import time
from datetime import datetime
import re

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("تحذير: مكتبة scapy غير مثبتة. سيتم تعطيل التقاط الشبكة.")

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from Crypto.Cipher import AES, DES
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("تحذير: مكتبات التشفير غير مثبتة. سيتم تعطيل بعض خيارات فك التشفير.")


class DecryptionEngine:
    """محرك فك التشفير"""
    
    def __init__(self):
        self.methods = {
            'base64': self.decode_base64,
            'caesar': self.decode_caesar,
            'rot13': self.decode_rot13,
            'hex': self.decode_hex,
            'url': self.decode_url,
            'aes': self.decode_aes,
            'custom': self.decode_custom
        }
    
    def decode_base64(self, data, key=None):
        """فك ترميز Base64"""
        try:
            if isinstance(data, str):
                data = data.encode()
            decoded = base64.b64decode(data)
            return decoded.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"خطأ في فك Base64: {str(e)}"
    
    def decode_caesar(self, data, key=None):
        """فك تشفير قيصر"""
        if not key:
            key = 3  # القيمة الافتراضية
        try:
            key = int(key)
            result = ""
            for char in data:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    result += chr((ord(char) - ascii_offset - key) % 26 + ascii_offset)
                else:
                    result += char
            return result
        except Exception as e:
            return f"خطأ في فك تشفير قيصر: {str(e)}"
    
    def decode_rot13(self, data, key=None):
        """فك تشفير ROT13"""
        return self.decode_caesar(data, 13)
    
    def decode_hex(self, data, key=None):
        """فك ترميز Hex"""
        try:
            # إزالة المسافات والرموز غير المرغوبة
            data = re.sub(r'[^0-9a-fA-F]', '', data)
            decoded = bytes.fromhex(data)
            return decoded.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"خطأ في فك Hex: {str(e)}"
    
    def decode_url(self, data, key=None):
        """فك ترميز URL"""
        try:
            import urllib.parse
            return urllib.parse.unquote(data)
        except Exception as e:
            return f"خطأ في فك URL: {str(e)}"
    
    def decode_aes(self, data, key=None):
        """فك تشفير AES"""
        if not CRYPTO_AVAILABLE or not key:
            return "مكتبات التشفير غير متوفرة أو المفتاح مفقود"
        
        try:
            # تحويل المفتاح إلى 32 بايت
            key_bytes = hashlib.sha256(key.encode()).digest()
            
            # فك ترميز البيانات من base64
            encrypted_data = base64.b64decode(data)
            
            # استخراج IV (أول 16 بايت)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # فك التشفير
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            return decrypted.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"خطأ في فك AES: {str(e)}"
    
    def decode_custom(self, data, key=None):
        """فك تشفير مخصص - يمكن تعديله حسب الحاجة"""
        try:
            # مثال على تشفير مخصص بسيط (XOR)
            if not key:
                key = "default"
            
            result = ""
            key_len = len(key)
            for i, char in enumerate(data):
                result += chr(ord(char) ^ ord(key[i % key_len]))
            
            return result
        except Exception as e:
            return f"خطأ في فك التشفير المخصص: {str(e)}"
    
    def auto_detect_and_decode(self, data):
        """محاولة فك التشفير تلقائياً"""
        results = {}
        
        for method_name, method_func in self.methods.items():
            if method_name in ['aes', 'custom']:
                continue  # تحتاج مفتاح
            
            try:
                result = method_func(data)
                if result and not result.startswith("خطأ"):
                    results[method_name] = result
            except:
                continue
        
        return results


class NetworkCapture:
    """التقاط الشبكة"""
    
    def __init__(self, callback):
        self.callback = callback
        self.is_capturing = False
        self.capture_thread = None
        self.packet_count = 0
    
    def start_capture(self, interface=None, filter_str=""):
        """بدء التقاط الشبكة"""
        if not SCAPY_AVAILABLE:
            self.callback("خطأ: مكتبة scapy غير مثبتة")
            return
        
        self.is_capturing = True
        self.packet_count = 0
        
        def capture_packets():
            try:
                sniff(
                    iface=interface,
                    filter=filter_str,
                    prn=self.process_packet,
                    stop_filter=lambda x: not self.is_capturing
                )
            except Exception as e:
                self.callback(f"خطأ في التقاط الشبكة: {str(e)}")
        
        self.capture_thread = threading.Thread(target=capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
    
    def stop_capture(self):
        """إيقاف التقاط الشبكة"""
        self.is_capturing = False
    
    def process_packet(self, packet):
        """معالجة الحزمة المُلتقطة"""
        try:
            if Raw in packet:
                raw_data = packet[Raw].load
                
                # محاولة فك ترميز البيانات
                try:
                    text_data = raw_data.decode('utf-8', errors='ignore')
                except:
                    text_data = str(raw_data)
                
                # معلومات الحزمة
                src_ip = packet[IP].src if IP in packet else "غير معروف"
                dst_ip = packet[IP].dst if IP in packet else "غير معروف"
                protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "أخرى"
                
                packet_info = {
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'data': text_data,
                    'raw_data': raw_data
                }
                
                self.packet_count += 1
                self.callback(packet_info)
                
        except Exception as e:
            pass  # تجاهل الأخطاء في معالجة الحزم


class NetworkDecryptorGUI:
    """الواجهة الرسومية الرئيسية"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("أداة فك تشفير رسائل الشبكة")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # المحركات
        self.decryption_engine = DecryptionEngine()
        self.network_capture = NetworkCapture(self.on_packet_received)
        
        # قائمة انتظار للرسائل
        self.message_queue = queue.Queue()
        
        # إعداد الواجهة
        self.setup_ui()
        
        # بدء معالجة الرسائل
        self.process_messages()
    
    def setup_ui(self):
        """إعداد الواجهة الرسومية"""
        
        # الشريط العلوي
        top_frame = tk.Frame(self.root, bg='#2b2b2b')
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # عنوان التطبيق
        title_label = tk.Label(
            top_frame, 
            text="🔓 أداة فك تشفير رسائل الشبكة", 
            font=('Arial', 16, 'bold'),
            fg='#00ff00',
            bg='#2b2b2b'
        )
        title_label.pack(pady=10)
        
        # إطار التحكم
        control_frame = tk.Frame(self.root, bg='#2b2b2b')
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # أزرار التحكم في التقاط الشبكة
        capture_frame = tk.LabelFrame(
            control_frame, 
            text="التقاط الشبكة", 
            fg='white', 
            bg='#2b2b2b',
            font=('Arial', 10, 'bold')
        )
        capture_frame.pack(fill=tk.X, pady=5)
        
        # إعدادات التقاط
        settings_frame = tk.Frame(capture_frame, bg='#2b2b2b')
        settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(settings_frame, text="واجهة الشبكة:", fg='white', bg='#2b2b2b').pack(side=tk.LEFT)
        self.interface_var = tk.StringVar(value="any")
        interface_entry = tk.Entry(settings_frame, textvariable=self.interface_var, width=15)
        interface_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(settings_frame, text="فلتر:", fg='white', bg='#2b2b2b').pack(side=tk.LEFT, padx=(20,0))
        self.filter_var = tk.StringVar(value="tcp or udp")
        filter_entry = tk.Entry(settings_frame, textvariable=self.filter_var, width=20)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        # أزرار التحكم
        button_frame = tk.Frame(capture_frame, bg='#2b2b2b')
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_button = tk.Button(
            button_frame,
            text="🚀 بدء التقاط",
            command=self.start_capture,
            bg='#4CAF50',
            fg='white',
            font=('Arial', 10, 'bold')
        )
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(
            button_frame,
            text="⏹️ إيقاف التقاط",
            command=self.stop_capture,
            bg='#f44336',
            fg='white',
            font=('Arial', 10, 'bold'),
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = tk.Button(
            button_frame,
            text="🗑️ مسح",
            command=self.clear_messages,
            bg='#FF9800',
            fg='white',
            font=('Arial', 10, 'bold')
        )
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # أزرار الميزات المتقدمة
        if hasattr(self, 'advanced_features') and self.advanced_features:
            self.save_session_button = tk.Button(
                button_frame,
                text="💾 حفظ الجلسة",
                command=self.save_session,
                bg='#9C27B0',
                fg='white',
                font=('Arial', 10, 'bold')
            )
            self.save_session_button.pack(side=tk.LEFT, padx=5)
            
            self.load_session_button = tk.Button(
                button_frame,
                text="📂 تحميل الجلسة",
                command=self.load_session,
                bg='#607D8B',
                fg='white',
                font=('Arial', 10, 'bold')
            )
            self.load_session_button.pack(side=tk.LEFT, padx=5)
            
            self.export_button = tk.Button(
                button_frame,
                text="📤 تصدير",
                command=self.export_data,
                bg='#795548',
                fg='white',
                font=('Arial', 10, 'bold')
            )
            self.export_button.pack(side=tk.LEFT, padx=5)
        
        # عداد الحزم
        self.packet_count_label = tk.Label(
            button_frame,
            text="الحزم المُلتقطة: 0",
            fg='#00ff00',
            bg='#2b2b2b',
            font=('Arial', 10)
        )
        self.packet_count_label.pack(side=tk.RIGHT, padx=5)
        
        # الإطار الرئيسي
        main_frame = tk.Frame(self.root, bg='#2b2b2b')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # الجانب الأيسر - الرسائل المُلتقطة
        left_frame = tk.LabelFrame(
            main_frame,
            text="الرسائل المُلتقطة",
            fg='white',
            bg='#2b2b2b',
            font=('Arial', 10, 'bold')
        )
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,5))
        
        # قائمة الرسائل
        self.messages_listbox = tk.Listbox(
            left_frame,
            bg='#1e1e1e',
            fg='white',
            selectbackground='#0078d4',
            font=('Consolas', 9)
        )
        self.messages_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.messages_listbox.bind('<<ListboxSelect>>', self.on_message_select)
        
        # الجانب الأيمن - فك التشفير
        right_frame = tk.LabelFrame(
            main_frame,
            text="فك التشفير",
            fg='white',
            bg='#2b2b2b',
            font=('Arial', 10, 'bold')
        )
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5,0))
        
        # إعدادات فك التشفير
        decrypt_settings_frame = tk.Frame(right_frame, bg='#2b2b2b')
        decrypt_settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(decrypt_settings_frame, text="نوع التشفير:", fg='white', bg='#2b2b2b').pack(side=tk.LEFT)
        self.decrypt_method_var = tk.StringVar(value="auto")
        decrypt_method_combo = ttk.Combobox(
            decrypt_settings_frame,
            textvariable=self.decrypt_method_var,
            values=["auto", "base64", "caesar", "rot13", "hex", "url", "aes", "custom", 
                   "custom_xor", "multi_caesar", "substitution", "transposition", 
                   "vigenere_advanced", "spiral", "zigzag", "book_cipher", "multi_type"],
            state="readonly",
            width=15
        )
        decrypt_method_combo.pack(side=tk.LEFT, padx=5)
        
        tk.Label(decrypt_settings_frame, text="المفتاح:", fg='white', bg='#2b2b2b').pack(side=tk.LEFT, padx=(20,0))
        self.key_var = tk.StringVar()
        key_entry = tk.Entry(decrypt_settings_frame, textvariable=self.key_var, width=20, show="*")
        key_entry.pack(side=tk.LEFT, padx=5)
        
        # زر فك التشفير
        decrypt_button = tk.Button(
            decrypt_settings_frame,
            text="🔓 فك التشفير",
            command=self.decrypt_selected,
            bg='#2196F3',
            fg='white',
            font=('Arial', 10, 'bold')
        )
        decrypt_button.pack(side=tk.RIGHT, padx=5)
        
        # منطقة النتائج
        results_frame = tk.Frame(right_frame, bg='#2b2b2b')
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # البيانات الأصلية
        tk.Label(results_frame, text="البيانات الأصلية:", fg='white', bg='#2b2b2b', font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        self.original_text = scrolledtext.ScrolledText(
            results_frame,
            height=8,
            bg='#1e1e1e',
            fg='white',
            font=('Consolas', 9)
        )
        self.original_text.pack(fill=tk.BOTH, expand=True, pady=(0,5))
        
        # النتيجة المفكوكة
        tk.Label(results_frame, text="النتيجة المفكوكة:", fg='white', bg='#2b2b2b', font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        self.decrypted_text = scrolledtext.ScrolledText(
            results_frame,
            height=8,
            bg='#1e1e1e',
            fg='#00ff00',
            font=('Consolas', 9)
        )
        self.decrypted_text.pack(fill=tk.BOTH, expand=True)
        
        # شريط الحالة
        self.status_bar = tk.Label(
            self.root,
            text="جاهز للاستخدام",
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg='#1e1e1e',
            fg='white'
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # قائمة لحفظ الرسائل
        self.captured_messages = []
        
        # إضافة مدير الجلسات ومحلل الحزم
        try:
            from session_manager import SessionManager, DataExporter
            from packet_analyzer import PacketAnalyzer, NetworkStatistics
            from custom_crypto import CustomCrypto, MultiTypeDecryption
            self.session_manager = SessionManager()
            self.data_exporter = DataExporter()
            self.packet_analyzer = PacketAnalyzer()
            self.network_stats = NetworkStatistics()
            self.custom_crypto = CustomCrypto()
            self.multi_decrypt = MultiTypeDecryption()
            self.advanced_features = True
        except ImportError:
            self.advanced_features = False
            print("تحذير: الميزات المتقدمة غير متوفرة")
    
    def start_capture(self):
        """بدء التقاط الشبكة"""
        interface = self.interface_var.get() if self.interface_var.get() != "any" else None
        filter_str = self.filter_var.get()
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        self.update_status("بدء التقاط الشبكة...")
        self.network_capture.start_capture(interface, filter_str)
    
    def stop_capture(self):
        """إيقاف التقاط الشبكة"""
        self.network_capture.stop_capture()
        
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        self.update_status("تم إيقاف التقاط الشبكة")
    
    def clear_messages(self):
        """مسح الرسائل"""
        self.messages_listbox.delete(0, tk.END)
        self.captured_messages.clear()
        self.original_text.delete(1.0, tk.END)
        self.decrypted_text.delete(1.0, tk.END)
        self.network_capture.packet_count = 0
        self.packet_count_label.config(text="الحزم المُلتقطة: 0")
        self.update_status("تم مسح جميع الرسائل")
    
    def on_packet_received(self, packet_info):
        """استقبال حزمة جديدة"""
        self.message_queue.put(packet_info)
    
    def process_messages(self):
        """معالجة الرسائل في قائمة الانتظار"""
        try:
            while True:
                packet_info = self.message_queue.get_nowait()
                
                # إضافة الرسالة للقائمة
                display_text = f"[{packet_info['timestamp']}] {packet_info['src_ip']} → {packet_info['dst_ip']} ({packet_info['protocol']})"
                self.messages_listbox.insert(tk.END, display_text)
                self.captured_messages.append(packet_info)
                
                # تحديث العداد
                count = len(self.captured_messages)
                self.packet_count_label.config(text=f"الحزم المُلتقطة: {count}")
                
                # التمرير للأسفل
                self.messages_listbox.see(tk.END)
                
        except queue.Empty:
            pass
        
        # إعادة جدولة المعالجة
        self.root.after(100, self.process_messages)
    
    def on_message_select(self, event):
        """عند اختيار رسالة"""
        selection = self.messages_listbox.curselection()
        if selection:
            index = selection[0]
            packet_info = self.captured_messages[index]
            
            # عرض البيانات الأصلية
            self.original_text.delete(1.0, tk.END)
            self.original_text.insert(1.0, packet_info['data'])
            
            # مسح النتيجة السابقة
            self.decrypted_text.delete(1.0, tk.END)
            
            self.update_status(f"تم اختيار رسالة من {packet_info['src_ip']}")
    
    def decrypt_selected(self):
        """فك تشفير الرسالة المختارة"""
        selection = self.messages_listbox.curselection()
        if not selection:
            messagebox.showwarning("تحذير", "يرجى اختيار رسالة أولاً")
            return
        
        index = selection[0]
        packet_info = self.captured_messages[index]
        data = packet_info['data']
        
        method = self.decrypt_method_var.get()
        key = self.key_var.get() if self.key_var.get() else None
        
        self.decrypted_text.delete(1.0, tk.END)
        
        if method == "auto":
            # فك تشفير تلقائي
            results = self.decryption_engine.auto_detect_and_decode(data)
            
            if results:
                output = "النتائج المحتملة:\n" + "="*50 + "\n\n"
                for method_name, result in results.items():
                    output += f"[{method_name.upper()}]\n{result}\n\n" + "-"*30 + "\n\n"
                self.decrypted_text.insert(1.0, output)
                self.update_status(f"تم العثور على {len(results)} نتيجة محتملة")
            else:
                self.decrypted_text.insert(1.0, "لم يتم العثور على نتائج مفهومة")
                self.update_status("لم يتم فك التشفير بنجاح")
        else:
            # فك تشفير محدد
            if method in self.decryption_engine.methods:
                result = self.decryption_engine.methods[method](data, key)
                self.decrypted_text.insert(1.0, result)
                self.update_status(f"تم فك التشفير باستخدام {method}")
            elif method == "multi_type" and hasattr(self, 'multi_decrypt'):
                # فك التشفير متعدد الأنواع
                results = self.multi_decrypt.try_all_methods(data)
                if results:
                    output = "النتائج المحتملة:\n" + "="*50 + "\n\n"
                    for method_name, (result, score) in results.items():
                        output += f"[{method_name.upper()}] (نتيجة: {score:.1f})\n"
                        output += f"{result}\n\n" + "-"*30 + "\n\n"
                    self.decrypted_text.insert(1.0, output)
                    self.update_status(f"تم العثور على {len(results)} نتيجة محتملة")
                else:
                    self.decrypted_text.insert(1.0, "لم يتم العثور على نتائج مفهومة")
                    self.update_status("فشل في فك التشفير")
            elif hasattr(self, 'custom_crypto') and method in ['custom_xor', 'multi_caesar', 'substitution', 'transposition', 'vigenere_advanced', 'spiral', 'zigzag', 'book_cipher']:
                # أنواع التشفير المخصص
                try:
                    if method == 'custom_xor':
                        result = self.custom_crypto.custom_xor_decrypt(data, key)
                    elif method == 'multi_caesar':
                        shifts = [3, 7, 11, 13, 17] if not key else [int(x) for x in key.split(',')]
                        result = self.custom_crypto.multi_caesar_decrypt(data, shifts)
                    elif method == 'substitution':
                        result = self.custom_crypto.substitution_decrypt(data)
                    elif method == 'transposition':
                        result = self.custom_crypto.transposition_decrypt(data, key)
                    elif method == 'vigenere_advanced':
                        result = self.custom_crypto.vigenere_advanced_decrypt(data, key)
                    elif method == 'spiral':
                        size = int(key) if key and key.isdigit() else None
                        result = self.custom_crypto.spiral_decrypt(data, size)
                    elif method == 'zigzag':
                        rails = int(key) if key and key.isdigit() else 3
                        result = self.custom_crypto.zigzag_decrypt(data, rails)
                    elif method == 'book_cipher':
                        result = self.custom_crypto.book_cipher_decrypt(data)
                    
                    self.decrypted_text.insert(1.0, result)
                    self.update_status(f"تم فك التشفير باستخدام {method}")
                    
                except Exception as e:
                    self.decrypted_text.insert(1.0, f"خطأ في فك التشفير: {str(e)}")
                    self.update_status("فشل في فك التشفير")
            else:
                self.decrypted_text.insert(1.0, "نوع التشفير غير مدعوم")
                self.update_status("نوع التشفير غير مدعوم")
    
    def update_status(self, message):
        """تحديث شريط الحالة"""
        self.status_bar.config(text=message)
    
    def save_session(self):
        """حفظ الجلسة الحالية"""
        if not hasattr(self, 'session_manager'):
            messagebox.showerror("خطأ", "مدير الجلسات غير متوفر")
            return
        
        # إعداد بيانات الجلسة
        session_data = {
            'packets': [],
            'decrypted_messages': [],
            'settings': {
                'interface': self.interface_var.get(),
                'filter': self.filter_var.get()
            }
        }
        
        # إضافة الرسائل المُلتقطة
        for msg in self.captured_messages:
            session_data['packets'].append({
                'timestamp': msg['timestamp'],
                'src_ip': msg['src_ip'],
                'dst_ip': msg['dst_ip'],
                'protocol': msg['protocol'],
                'data': msg['data']
            })
        
        # طلب اسم الجلسة
        session_name = simpledialog.askstring("حفظ الجلسة", "أدخل اسم الجلسة:")
        if session_name:
            try:
                session_file = self.session_manager.save_session(session_data, session_name)
                messagebox.showinfo("نجح", f"تم حفظ الجلسة في:\n{session_file}")
                self.update_status(f"تم حفظ الجلسة: {session_name}")
            except Exception as e:
                messagebox.showerror("خطأ", f"فشل في حفظ الجلسة:\n{str(e)}")
    
    def load_session(self):
        """تحميل جلسة محفوظة"""
        if not hasattr(self, 'session_manager'):
            messagebox.showerror("خطأ", "مدير الجلسات غير متوفر")
            return
        
        # عرض قائمة الجلسات
        sessions = self.session_manager.list_sessions()
        if not sessions:
            messagebox.showinfo("معلومات", "لا توجد جلسات محفوظة")
            return
        
        # إنشاء نافذة اختيار الجلسة
        session_window = tk.Toplevel(self.root)
        session_window.title("تحميل الجلسة")
        session_window.geometry("600x400")
        session_window.configure(bg='#2b2b2b')
        
        # قائمة الجلسات
        sessions_listbox = tk.Listbox(
            session_window,
            bg='#1e1e1e',
            fg='white',
            selectbackground='#0078d4',
            font=('Consolas', 9)
        )
        sessions_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # إضافة الجلسات للقائمة
        for session in sessions:
            display_text = f"{session['name']} - {session['timestamp']} ({session['size']} bytes)"
            sessions_listbox.insert(tk.END, display_text)
        
        # أزرار التحكم
        button_frame = tk.Frame(session_window, bg='#2b2b2b')
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        def load_selected():
            selection = sessions_listbox.curselection()
            if selection:
                selected_session = sessions[selection[0]]
                try:
                    session_info = self.session_manager.load_session(selected_session['filepath'])
                    self.load_session_data(session_info['data'])
                    session_window.destroy()
                    messagebox.showinfo("نجح", f"تم تحميل الجلسة: {selected_session['name']}")
                    self.update_status(f"تم تحميل الجلسة: {selected_session['name']}")
                except Exception as e:
                    messagebox.showerror("خطأ", f"فشل في تحميل الجلسة:\n{str(e)}")
        
        tk.Button(
            button_frame,
            text="تحميل",
            command=load_selected,
            bg='#4CAF50',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            button_frame,
            text="إلغاء",
            command=session_window.destroy,
            bg='#f44336',
            fg='white'
        ).pack(side=tk.LEFT, padx=5)
    
    def load_session_data(self, session_data):
        """تحميل بيانات الجلسة"""
        # مسح البيانات الحالية
        self.clear_messages()
        
        # تحميل الحزم
        packets = session_data.get('packets', [])
        for packet in packets:
            # إضافة الرسالة للقائمة
            display_text = f"[{packet['timestamp']}] {packet['src_ip']} → {packet['dst_ip']} ({packet['protocol']})"
            self.messages_listbox.insert(tk.END, display_text)
            self.captured_messages.append(packet)
        
        # تحديث العداد
        count = len(self.captured_messages)
        self.packet_count_label.config(text=f"الحزم المُلتقطة: {count}")
        
        # تحميل الإعدادات
        settings = session_data.get('settings', {})
        if 'interface' in settings:
            self.interface_var.set(settings['interface'])
        if 'filter' in settings:
            self.filter_var.set(settings['filter'])
    
    def export_data(self):
        """تصدير البيانات"""
        if not hasattr(self, 'data_exporter'):
            messagebox.showerror("خطأ", "مصدر البيانات غير متوفر")
            return
        
        if not self.captured_messages:
            messagebox.showwarning("تحذير", "لا توجد بيانات للتصدير")
            return
        
        # اختيار نوع التصدير
        export_window = tk.Toplevel(self.root)
        export_window.title("تصدير البيانات")
        export_window.geometry("400x300")
        export_window.configure(bg='#2b2b2b')
        
        tk.Label(
            export_window,
            text="اختر صيغة التصدير:",
            fg='white',
            bg='#2b2b2b',
            font=('Arial', 12, 'bold')
        ).pack(pady=10)
        
        format_var = tk.StringVar(value="json")
        formats = [
            ("JSON", "json"),
            ("CSV", "csv"),
            ("HTML", "html"),
            ("XML", "xml"),
            ("TXT", "txt")
        ]
        
        for text, value in formats:
            tk.Radiobutton(
                export_window,
                text=text,
                variable=format_var,
                value=value,
                fg='white',
                bg='#2b2b2b',
                selectcolor='#1e1e1e'
            ).pack(anchor=tk.W, padx=20)
        
        def do_export():
            format_type = format_var.get()
            filename = filedialog.asksaveasfilename(
                defaultextension=f".{format_type}",
                filetypes=[(format_type.upper(), f"*.{format_type}")]
            )
            
            if filename:
                try:
                    self.data_exporter.export_packets(self.captured_messages, filename, format_type)
                    export_window.destroy()
                    messagebox.showinfo("نجح", f"تم تصدير البيانات إلى:\n{filename}")
                    self.update_status(f"تم تصدير البيانات بصيغة {format_type.upper()}")
                except Exception as e:
                    messagebox.showerror("خطأ", f"فشل في التصدير:\n{str(e)}")
        
        tk.Button(
            export_window,
            text="تصدير",
            command=do_export,
            bg='#4CAF50',
            fg='white',
            font=('Arial', 10, 'bold')
        ).pack(pady=20)
        
        tk.Button(
            export_window,
            text="إلغاء",
            command=export_window.destroy,
            bg='#f44336',
            fg='white',
            font=('Arial', 10, 'bold')
        ).pack()
    
    def run(self):
        """تشغيل التطبيق"""
        self.root.mainloop()


def main():
    """الدالة الرئيسية"""
    print("🔓 أداة فك تشفير رسائل الشبكة")
    print("="*50)
    
    if not SCAPY_AVAILABLE:
        print("⚠️  تحذير: مكتبة scapy غير مثبتة")
        print("لتثبيتها: pip install scapy")
        print()
    
    if not CRYPTO_AVAILABLE:
        print("⚠️  تحذير: مكتبات التشفير غير مثبتة")
        print("لتثبيتها: pip install cryptography pycryptodome")
        print()
    
    # تشغيل التطبيق
    app = NetworkDecryptorGUI()
    app.run()


if __name__ == "__main__":
    main()