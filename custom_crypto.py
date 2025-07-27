#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أدوات التشفير المخصص ومتعدد الأنواع
Custom and Multi-Type Encryption Tools
"""

import base64
import hashlib
import hmac
import random
import string
import json
from itertools import cycle
import re

try:
    from Crypto.Cipher import AES, DES, Blowfish
    from Crypto.PublicKey import RSA, ECC
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class CustomCrypto:
    """فئة التشفير المخصص"""
    
    def __init__(self):
        self.algorithms = {
            'custom_xor': self.custom_xor_encrypt,
            'multi_caesar': self.multi_caesar_encrypt,
            'substitution': self.substitution_encrypt,
            'transposition': self.transposition_encrypt,
            'vigenere_advanced': self.vigenere_advanced_encrypt,
            'spiral': self.spiral_encrypt,
            'zigzag': self.zigzag_encrypt,
            'book_cipher': self.book_cipher_encrypt
        }
        
        # مفاتيح التشفير المختلفة
        self.substitution_key = self.generate_substitution_key()
        self.book_text = "The quick brown fox jumps over the lazy dog"
    
    def generate_substitution_key(self):
        """إنشاء مفتاح الاستبدال"""
        alphabet = string.ascii_lowercase
        shuffled = list(alphabet)
        random.shuffle(shuffled)
        return dict(zip(alphabet, shuffled))
    
    def custom_xor_encrypt(self, text, key=None):
        """تشفير XOR مخصص مع مفتاح متغير"""
        if not key:
            key = "dynamic_key_2024"
        
        # توليد مفتاح ديناميكي
        dynamic_key = ""
        for i, char in enumerate(text):
            key_char = key[i % len(key)]
            # تعديل المفتاح بناءً على موضع الحرف
            modified_key = chr((ord(key_char) + i) % 256)
            dynamic_key += modified_key
        
        # تطبيق XOR
        result = ""
        for i, char in enumerate(text):
            result += chr(ord(char) ^ ord(dynamic_key[i]))
        
        return base64.b64encode(result.encode('latin-1')).decode()
    
    def custom_xor_decrypt(self, encrypted_text, key=None):
        """فك تشفير XOR المخصص"""
        if not key:
            key = "dynamic_key_2024"
        
        try:
            # فك ترميز Base64
            encrypted_bytes = base64.b64decode(encrypted_text).decode('latin-1')
            
            # إعادة بناء المفتاح الديناميكي
            dynamic_key = ""
            for i in range(len(encrypted_bytes)):
                key_char = key[i % len(key)]
                modified_key = chr((ord(key_char) + i) % 256)
                dynamic_key += modified_key
            
            # فك التشفير
            result = ""
            for i, char in enumerate(encrypted_bytes):
                result += chr(ord(char) ^ ord(dynamic_key[i]))
            
            return result
        except:
            return "خطأ في فك التشفير"
    
    def multi_caesar_encrypt(self, text, shifts=None):
        """تشفير قيصر متعدد الإزاحات"""
        if not shifts:
            shifts = [3, 7, 11, 13, 17]  # إزاحات مختلفة
        
        result = ""
        for i, char in enumerate(text):
            if char.isalpha():
                shift = shifts[i % len(shifts)]
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        
        return result
    
    def multi_caesar_decrypt(self, text, shifts=None):
        """فك تشفير قيصر متعدد الإزاحات"""
        if not shifts:
            shifts = [3, 7, 11, 13, 17]
        
        result = ""
        for i, char in enumerate(text):
            if char.isalpha():
                shift = shifts[i % len(shifts)]
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            else:
                result += char
        
        return result
    
    def substitution_encrypt(self, text, key=None):
        """تشفير الاستبدال"""
        if not key:
            key = self.substitution_key
        
        result = ""
        for char in text.lower():
            if char in key:
                result += key[char]
            else:
                result += char
        
        return result
    
    def substitution_decrypt(self, text, key=None):
        """فك تشفير الاستبدال"""
        if not key:
            key = self.substitution_key
        
        # عكس المفتاح
        reverse_key = {v: k for k, v in key.items()}
        
        result = ""
        for char in text.lower():
            if char in reverse_key:
                result += reverse_key[char]
            else:
                result += char
        
        return result
    
    def transposition_encrypt(self, text, key=None):
        """تشفير التبديل"""
        if not key:
            key = "CRYPTO"
        
        # ترتيب الأعمدة حسب المفتاح
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        
        # تقسيم النص إلى صفوف
        rows = []
        for i in range(0, len(text), len(key)):
            row = text[i:i+len(key)]
            # إضافة حشو إذا لزم الأمر
            while len(row) < len(key):
                row += 'X'
            rows.append(row)
        
        # قراءة الأعمدة حسب الترتيب
        result = ""
        for col_index in key_order:
            for row in rows:
                if col_index < len(row):
                    result += row[col_index]
        
        return result
    
    def transposition_decrypt(self, text, key=None):
        """فك تشفير التبديل"""
        if not key:
            key = "CRYPTO"
        
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        num_rows = len(text) // len(key)
        
        # إعادة بناء الجدول
        cols = [''] * len(key)
        text_index = 0
        
        for col_index in key_order:
            for _ in range(num_rows):
                if text_index < len(text):
                    cols[col_index] += text[text_index]
                    text_index += 1
        
        # قراءة الصفوف
        result = ""
        for row in range(num_rows):
            for col in range(len(key)):
                if row < len(cols[col]):
                    result += cols[col][row]
        
        return result.rstrip('X')  # إزالة الحشو
    
    def vigenere_advanced_encrypt(self, text, key=None):
        """تشفير Vigenère متقدم مع مفتاح متغير"""
        if not key:
            key = "ADVANCED"
        
        # توليد مفتاح متغير
        extended_key = ""
        for i, char in enumerate(text):
            if char.isalpha():
                # تعديل المفتاح بناءً على الموضع
                key_char = key[i % len(key)]
                modified_char = chr((ord(key_char) - ord('A') + i) % 26 + ord('A'))
                extended_key += modified_char
            else:
                extended_key += char
        
        # تطبيق Vigenère
        result = ""
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(extended_key[key_index]) - ord('A')
                if char.isupper():
                    result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                key_index += 1
            else:
                result += char
                key_index += 1
        
        return result
    
    def vigenere_advanced_decrypt(self, text, key=None):
        """فك تشفير Vigenère المتقدم"""
        if not key:
            key = "ADVANCED"
        
        # إعادة بناء المفتاح المتغير
        extended_key = ""
        for i, char in enumerate(text):
            if char.isalpha():
                key_char = key[i % len(key)]
                modified_char = chr((ord(key_char) - ord('A') + i) % 26 + ord('A'))
                extended_key += modified_char
            else:
                extended_key += char
        
        # فك التشفير
        result = ""
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(extended_key[key_index]) - ord('A')
                if char.isupper():
                    result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                key_index += 1
            else:
                result += char
                key_index += 1
        
        return result
    
    def spiral_encrypt(self, text, size=None):
        """تشفير حلزوني"""
        if not size:
            size = int(len(text) ** 0.5) + 1
        
        # إنشاء مصفوفة
        matrix = [['' for _ in range(size)] for _ in range(size)]
        
        # ملء المصفوفة بشكل حلزوني
        directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]  # يمين، أسفل، يسار، أعلى
        direction = 0
        row, col = 0, 0
        
        for i, char in enumerate(text):
            matrix[row][col] = char
            
            # حساب الموضع التالي
            next_row = row + directions[direction][0]
            next_col = col + directions[direction][1]
            
            # تغيير الاتجاه إذا لزم الأمر
            if (next_row < 0 or next_row >= size or 
                next_col < 0 or next_col >= size or 
                matrix[next_row][next_col] != ''):
                direction = (direction + 1) % 4
                next_row = row + directions[direction][0]
                next_col = col + directions[direction][1]
            
            row, col = next_row, next_col
        
        # قراءة المصفوفة بشكل عادي
        result = ""
        for row in matrix:
            for cell in row:
                if cell:
                    result += cell
        
        return result
    
    def spiral_decrypt(self, text, size=None):
        """فك التشفير الحلزوني"""
        if not size:
            size = int(len(text) ** 0.5) + 1
        
        # إنشاء مصفوفة وملؤها بالنص
        matrix = [['' for _ in range(size)] for _ in range(size)]
        text_index = 0
        
        for i in range(size):
            for j in range(size):
                if text_index < len(text):
                    matrix[i][j] = text[text_index]
                    text_index += 1
        
        # قراءة بشكل حلزوني
        result = ""
        directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]
        direction = 0
        row, col = 0, 0
        visited = set()
        
        for _ in range(len(text)):
            if (row, col) not in visited and 0 <= row < size and 0 <= col < size:
                result += matrix[row][col]
                visited.add((row, col))
                
                # حساب الموضع التالي
                next_row = row + directions[direction][0]
                next_col = col + directions[direction][1]
                
                # تغيير الاتجاه إذا لزم الأمر
                if ((next_row, next_col) in visited or
                    next_row < 0 or next_row >= size or 
                    next_col < 0 or next_col >= size):
                    direction = (direction + 1) % 4
                    next_row = row + directions[direction][0]
                    next_col = col + directions[direction][1]
                
                row, col = next_row, next_col
        
        return result
    
    def zigzag_encrypt(self, text, rails=3):
        """تشفير متعرج (Rail Fence متقدم)"""
        if rails == 1:
            return text
        
        # إنشاء قضبان
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for char in text:
            fence[rail].append(char)
            rail += direction
            
            if rail == rails - 1 or rail == 0:
                direction *= -1
        
        # دمج القضبان
        result = ""
        for rail_chars in fence:
            result += ''.join(rail_chars)
        
        return result
    
    def zigzag_decrypt(self, text, rails=3):
        """فك التشفير المتعرج"""
        if rails == 1:
            return text
        
        # حساب طول كل قضيب
        rail_lengths = [0] * rails
        rail = 0
        direction = 1
        
        for _ in text:
            rail_lengths[rail] += 1
            rail += direction
            
            if rail == rails - 1 or rail == 0:
                direction *= -1
        
        # توزيع الأحرف على القضبان
        fence = []
        start = 0
        for length in rail_lengths:
            fence.append(list(text[start:start + length]))
            start += length
        
        # إعادة بناء النص
        result = ""
        rail = 0
        direction = 1
        rail_indices = [0] * rails
        
        for _ in text:
            result += fence[rail][rail_indices[rail]]
            rail_indices[rail] += 1
            rail += direction
            
            if rail == rails - 1 or rail == 0:
                direction *= -1
        
        return result
    
    def book_cipher_encrypt(self, text, book_text=None):
        """تشفير الكتاب"""
        if not book_text:
            book_text = self.book_text
        
        # إنشاء فهرس للكلمات
        words = book_text.lower().split()
        word_positions = {}
        
        for i, word in enumerate(words):
            clean_word = re.sub(r'[^a-z]', '', word)
            if clean_word not in word_positions:
                word_positions[clean_word] = []
            word_positions[clean_word].append(i)
        
        # تشفير النص
        result = []
        text_words = text.lower().split()
        
        for word in text_words:
            clean_word = re.sub(r'[^a-z]', '', word)
            if clean_word in word_positions:
                # اختيار موضع عشوائي للكلمة
                positions = word_positions[clean_word]
                chosen_position = random.choice(positions)
                result.append(str(chosen_position))
            else:
                result.append(f"?{word}")  # كلمة غير موجودة
        
        return ','.join(result)
    
    def book_cipher_decrypt(self, encrypted_text, book_text=None):
        """فك تشفير الكتاب"""
        if not book_text:
            book_text = self.book_text
        
        words = book_text.lower().split()
        positions = encrypted_text.split(',')
        
        result = []
        for pos in positions:
            if pos.startswith('?'):
                result.append(pos[1:])  # كلمة غير مشفرة
            else:
                try:
                    index = int(pos)
                    if 0 <= index < len(words):
                        result.append(words[index])
                    else:
                        result.append(f"[{pos}]")  # موضع غير صحيح
                except ValueError:
                    result.append(f"[{pos}]")
        
        return ' '.join(result)


class MultiTypeDecryption:
    """فئة فك التشفير متعدد الأنواع"""
    
    def __init__(self):
        self.custom_crypto = CustomCrypto()
        self.decryption_methods = {
            'custom_xor': self.custom_crypto.custom_xor_decrypt,
            'multi_caesar': self.custom_crypto.multi_caesar_decrypt,
            'substitution': self.custom_crypto.substitution_decrypt,
            'transposition': self.custom_crypto.transposition_decrypt,
            'vigenere_advanced': self.custom_crypto.vigenere_advanced_decrypt,
            'spiral': self.custom_crypto.spiral_decrypt,
            'zigzag': self.custom_crypto.zigzag_decrypt,
            'book_cipher': self.custom_crypto.book_cipher_decrypt
        }
    
    def detect_encryption_type(self, data):
        """كشف نوع التشفير تلقائياً"""
        patterns = {
            'base64': r'^[A-Za-z0-9+/]*={0,2}$',
            'hex': r'^[0-9a-fA-F\s]+$',
            'custom_xor': r'^[A-Za-z0-9+/]+=*$',  # يشبه Base64
            'book_cipher': r'^\d+(,\d+)*$',  # أرقام مفصولة بفواصل
            'multi_caesar': r'^[A-Za-z\s!@#$%^&*(),.?":{}|<>]+$'  # نص عادي
        }
        
        detected_types = []
        for crypto_type, pattern in patterns.items():
            if re.match(pattern, data.strip()):
                detected_types.append(crypto_type)
        
        return detected_types
    
    def try_all_methods(self, encrypted_data, max_attempts=5):
        """تجربة جميع طرق فك التشفير"""
        results = {}
        
        # كشف الأنواع المحتملة أولاً
        detected_types = self.detect_encryption_type(encrypted_data)
        
        # تجربة الطرق المكتشفة أولاً
        for crypto_type in detected_types:
            if crypto_type in self.decryption_methods:
                try:
                    result = self.decryption_methods[crypto_type](encrypted_data)
                    if result and not result.startswith("خطأ"):
                        score = self.calculate_readability_score(result)
                        results[crypto_type] = (result, score)
                except:
                    continue
        
        # تجربة باقي الطرق
        for method_name, method_func in self.decryption_methods.items():
            if method_name not in detected_types:
                try:
                    result = method_func(encrypted_data)
                    if result and not result.startswith("خطأ"):
                        score = self.calculate_readability_score(result)
                        results[method_name] = (result, score)
                except:
                    continue
        
        # ترتيب النتائج حسب النتيجة
        sorted_results = sorted(results.items(), key=lambda x: x[1][1], reverse=True)
        return dict(sorted_results[:max_attempts])
    
    def calculate_readability_score(self, text):
        """حساب نتيجة قابلية القراءة"""
        if not text:
            return 0
        
        score = 0
        
        # نسبة الأحرف الأبجدية
        alpha_ratio = sum(1 for c in text if c.isalpha()) / len(text)
        score += alpha_ratio * 30
        
        # نسبة المسافات (للكلمات)
        space_ratio = text.count(' ') / len(text)
        score += min(space_ratio * 100, 20)  # حد أقصى 20
        
        # وجود كلمات شائعة
        common_words = ['the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by']
        text_lower = text.lower()
        word_score = sum(5 for word in common_words if word in text_lower)
        score += min(word_score, 30)  # حد أقصى 30
        
        # تنوع الأحرف
        unique_chars = len(set(text.lower()))
        if unique_chars > 10:
            score += 20
        
        return min(score, 100)  # حد أقصى 100


def test_custom_crypto():
    """اختبار التشفير المخصص"""
    print("🔧 اختبار التشفير المخصص")
    print("=" * 40)
    
    crypto = CustomCrypto()
    multi_decrypt = MultiTypeDecryption()
    
    test_message = "Hello World! This is a test message."
    
    # اختبار كل نوع تشفير
    for method_name in crypto.algorithms.keys():
        print(f"\n🔐 اختبار {method_name}:")
        
        try:
            # التشفير
            if method_name == 'custom_xor':
                encrypted = crypto.custom_xor_encrypt(test_message)
                decrypted = crypto.custom_xor_decrypt(encrypted)
            elif method_name == 'multi_caesar':
                encrypted = crypto.multi_caesar_encrypt(test_message)
                decrypted = crypto.multi_caesar_decrypt(encrypted)
            elif method_name == 'substitution':
                encrypted = crypto.substitution_encrypt(test_message)
                decrypted = crypto.substitution_decrypt(encrypted)
            elif method_name == 'transposition':
                encrypted = crypto.transposition_encrypt(test_message)
                decrypted = crypto.transposition_decrypt(encrypted)
            elif method_name == 'vigenere_advanced':
                encrypted = crypto.vigenere_advanced_encrypt(test_message)
                decrypted = crypto.vigenere_advanced_decrypt(encrypted)
            elif method_name == 'spiral':
                encrypted = crypto.spiral_encrypt(test_message)
                decrypted = crypto.spiral_decrypt(encrypted)
            elif method_name == 'zigzag':
                encrypted = crypto.zigzag_encrypt(test_message)
                decrypted = crypto.zigzag_decrypt(encrypted)
            elif method_name == 'book_cipher':
                encrypted = crypto.book_cipher_encrypt(test_message)
                decrypted = crypto.book_cipher_decrypt(encrypted)
            
            print(f"  مشفر: {encrypted[:50]}{'...' if len(encrypted) > 50 else ''}")
            print(f"  مفكوك: {decrypted}")
            
            # التحقق من صحة فك التشفير
            success = test_message.lower() in decrypted.lower()
            print(f"  النتيجة: {'✅ نجح' if success else '❌ فشل'}")
            
        except Exception as e:
            print(f"  ❌ خطأ: {str(e)}")
    
    # اختبار فك التشفير التلقائي
    print(f"\n🤖 اختبار فك التشفير التلقائي:")
    encrypted_sample = crypto.custom_xor_encrypt("Secret message for testing")
    
    results = multi_decrypt.try_all_methods(encrypted_sample)
    print(f"عدد النتائج: {len(results)}")
    
    for method, (result, score) in results.items():
        print(f"  {method}: {result[:30]}... (نتيجة: {score:.1f})")


if __name__ == "__main__":
    test_custom_crypto()