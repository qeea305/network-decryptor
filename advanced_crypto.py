#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أدوات التشفير المتقدمة
Advanced Cryptography Tools
"""

import hashlib
import hmac
import base64
import binascii
import string
import itertools
from collections import Counter
import re

try:
    from Crypto.Cipher import AES, DES, Blowfish
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Util.Padding import unpad, pad
    from Crypto.Random import get_random_bytes
    PYCRYPTO_AVAILABLE = True
except ImportError:
    PYCRYPTO_AVAILABLE = False


class AdvancedDecryption:
    """فئة التشفير المتقدم"""
    
    def __init__(self):
        self.common_keys = [
            "password", "123456", "admin", "secret", "key", "default",
            "qwerty", "letmein", "welcome", "monkey", "dragon"
        ]
    
    def decode_base64(self, data):
        """فك ترميز Base64"""
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except:
            return "خطأ في فك Base64"
    
    def decode_hex(self, data):
        """فك ترميز Hex"""
        try:
            clean_data = re.sub(r'[^0-9a-fA-F]', '', data)
            return bytes.fromhex(clean_data).decode('utf-8', errors='ignore')
        except:
            return "خطأ في فك Hex"
    
    def decode_caesar(self, text, shift):
        """فك تشفير قيصر"""
        try:
            result = ""
            for char in text:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                else:
                    result += char
            return result
        except:
            return "خطأ في فك Caesar"
    
    def decode_rot13(self, text):
        """فك تشفير ROT13"""
        return self.decode_caesar(text, 13)
    
    def frequency_analysis(self, text):
        """تحليل التكرار للنص"""
        if not text:
            return {}
        
        # حساب تكرار الأحرف
        freq = Counter(text.lower())
        total = len(text)
        
        # تحويل إلى نسب مئوية
        freq_percent = {char: (count/total)*100 for char, count in freq.items()}
        
        return freq_percent
    
    def detect_encoding(self, data):
        """كشف نوع الترميز"""
        results = []
        
        # فحص Base64
        try:
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', data) and len(data) % 4 == 0:
                decoded = base64.b64decode(data)
                results.append(("base64", decoded.decode('utf-8', errors='ignore')))
        except:
            pass
        
        # فحص Hex
        try:
            if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
                decoded = bytes.fromhex(data)
                results.append(("hex", decoded.decode('utf-8', errors='ignore')))
        except:
            pass
        
        # فحص URL encoding
        try:
            if '%' in data:
                import urllib.parse
                decoded = urllib.parse.unquote(data)
                results.append(("url", decoded))
        except:
            pass
        
        return results
    
    def brute_force_caesar(self, text, max_shift=26):
        """كسر تشفير قيصر بالقوة الغاشمة"""
        results = []
        
        for shift in range(1, max_shift + 1):
            decrypted = ""
            for char in text:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    decrypted += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                else:
                    decrypted += char
            
            # تقييم جودة النتيجة
            score = self.calculate_text_score(decrypted)
            results.append((shift, decrypted, score))
        
        # ترتيب حسب النتيجة
        results.sort(key=lambda x: x[2], reverse=True)
        return results
    
    def calculate_text_score(self, text):
        """حساب نتيجة جودة النص"""
        if not text:
            return 0
        
        # تكرار الأحرف الشائعة في اللغة الإنجليزية
        english_freq = {
            'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
            's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8
        }
        
        text_freq = self.frequency_analysis(text.lower())
        score = 0
        
        for char, expected_freq in english_freq.items():
            actual_freq = text_freq.get(char, 0)
            score += abs(expected_freq - actual_freq)
        
        # كلما قل الرقم، كلما كان النص أقرب للإنجليزية
        return 100 - score
    
    def xor_decrypt(self, data, key):
        """فك تشفير XOR"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        
        result = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        
        try:
            return result.decode('utf-8', errors='ignore')
        except:
            return str(result)
    
    def brute_force_xor(self, data, max_key_length=10):
        """كسر XOR بالقوة الغاشمة"""
        results = []
        
        # تجربة مفاتيح بطول واحد
        for i in range(256):
            key = bytes([i])
            try:
                decrypted = self.xor_decrypt(data, key)
                score = self.calculate_text_score(decrypted)
                if score > 50:  # عتبة الجودة
                    results.append((key.hex(), decrypted, score))
            except:
                continue
        
        # تجربة مفاتيح نصية شائعة
        for key_text in self.common_keys:
            try:
                decrypted = self.xor_decrypt(data, key_text)
                score = self.calculate_text_score(decrypted)
                if score > 30:
                    results.append((key_text, decrypted, score))
            except:
                continue
        
        results.sort(key=lambda x: x[2], reverse=True)
        return results[:10]  # أفضل 10 نتائج
    
    def vigenere_decrypt(self, text, key):
        """فك تشفير Vigenère"""
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                if char.isupper():
                    result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                key_index += 1
            else:
                result += char
        
        return result
    
    def detect_vigenere_key_length(self, text, max_length=20):
        """كشف طول مفتاح Vigenère"""
        text = ''.join(c for c in text if c.isalpha()).upper()
        
        if len(text) < 50:
            return []
        
        # حساب مؤشر التطابق لكل طول مفتاح محتمل
        ic_scores = []
        
        for key_length in range(1, min(max_length + 1, len(text) // 4)):
            # تقسيم النص إلى مجموعات
            groups = [''] * key_length
            for i, char in enumerate(text):
                groups[i % key_length] += char
            
            # حساب متوسط مؤشر التطابق
            total_ic = 0
            for group in groups:
                if len(group) > 1:
                    total_ic += self.calculate_index_of_coincidence(group)
            
            avg_ic = total_ic / key_length if key_length > 0 else 0
            ic_scores.append((key_length, avg_ic))
        
        # ترتيب حسب مؤشر التطابق (الأعلى أفضل)
        ic_scores.sort(key=lambda x: x[1], reverse=True)
        return ic_scores[:5]
    
    def calculate_index_of_coincidence(self, text):
        """حساب مؤشر التطابق"""
        if len(text) < 2:
            return 0
        
        freq = Counter(text)
        n = len(text)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return ic
    
    def rail_fence_decrypt(self, text, rails):
        """فك تشفير Rail Fence"""
        if rails == 1:
            return text
        
        # إنشاء شبكة فارغة
        fence = [['' for _ in range(len(text))] for _ in range(rails)]
        
        # تحديد مواضع الأحرف
        rail = 0
        direction = 1
        
        for i in range(len(text)):
            fence[rail][i] = '*'
            rail += direction
            
            if rail == rails - 1 or rail == 0:
                direction *= -1
        
        # ملء الشبكة بالأحرف
        index = 0
        for r in range(rails):
            for c in range(len(text)):
                if fence[r][c] == '*':
                    fence[r][c] = text[index]
                    index += 1
        
        # قراءة النتيجة
        result = ""
        rail = 0
        direction = 1
        
        for i in range(len(text)):
            result += fence[rail][i]
            rail += direction
            
            if rail == rails - 1 or rail == 0:
                direction *= -1
        
        return result
    
    def atbash_decrypt(self, text):
        """فك تشفير Atbash"""
        result = ""
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result += chr(ord('Z') - (ord(char) - ord('A')))
                else:
                    result += chr(ord('z') - (ord(char) - ord('a')))
            else:
                result += char
        return result
    
    def morse_decrypt(self, text):
        """فك تشفير مورس"""
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6',
            '--...': '7', '---..': '8', '----.': '9'
        }
        
        # تنظيف النص
        text = text.replace('/', ' ').replace('|', ' ')
        words = text.split('  ')  # كلمات منفصلة بمسافتين
        
        result = ""
        for word in words:
            letters = word.split(' ')
            for letter in letters:
                if letter in morse_dict:
                    result += morse_dict[letter]
                elif letter:
                    result += '?'
            result += ' '
        
        return result.strip()
    
    def binary_decrypt(self, text):
        """فك ترميز ثنائي"""
        # إزالة المسافات والرموز غير المرغوبة
        binary = re.sub(r'[^01]', '', text)
        
        if len(binary) % 8 != 0:
            return "خطأ: طول البيانات الثنائية يجب أن يكون مضاعف 8"
        
        result = ""
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            try:
                char_code = int(byte, 2)
                if 32 <= char_code <= 126:  # أحرف قابلة للطباعة
                    result += chr(char_code)
                else:
                    result += f"\\x{char_code:02x}"
            except ValueError:
                result += "?"
        
        return result
    
    def analyze_all_methods(self, data):
        """تحليل شامل بجميع الطرق"""
        results = {}
        
        # الطرق البسيطة
        simple_methods = {
            'base64': lambda x: base64.b64decode(x).decode('utf-8', errors='ignore'),
            'hex': lambda x: bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', x)).decode('utf-8', errors='ignore'),
            'atbash': self.atbash_decrypt,
            'morse': self.morse_decrypt,
            'binary': self.binary_decrypt
        }
        
        for method_name, method_func in simple_methods.items():
            try:
                result = method_func(data)
                if result and not result.startswith("خطأ"):
                    score = self.calculate_text_score(result)
                    if score > 20:  # عتبة الجودة
                        results[method_name] = (result, score)
            except:
                continue
        
        # تشفير قيصر
        try:
            caesar_results = self.brute_force_caesar(data, 26)
            if caesar_results:
                best_caesar = caesar_results[0]
                if best_caesar[2] > 30:
                    results[f'caesar_shift_{best_caesar[0]}'] = (best_caesar[1], best_caesar[2])
        except:
            pass
        
        # XOR
        try:
            xor_results = self.brute_force_xor(data, 5)
            if xor_results:
                best_xor = xor_results[0]
                if best_xor[2] > 30:
                    results[f'xor_key_{best_xor[0]}'] = (best_xor[1], best_xor[2])
        except:
            pass
        
        # Rail Fence
        for rails in range(2, min(10, len(data) // 2)):
            try:
                result = self.rail_fence_decrypt(data, rails)
                score = self.calculate_text_score(result)
                if score > 30:
                    results[f'railfence_{rails}_rails'] = (result, score)
            except:
                continue
        
        # ترتيب النتائج حسب النتيجة
        sorted_results = sorted(results.items(), key=lambda x: x[1][1], reverse=True)
        return dict(sorted_results[:10])  # أفضل 10 نتائج


def test_advanced_crypto():
    """اختبار أدوات التشفير المتقدمة"""
    crypto = AdvancedDecryption()
    
    # اختبار تشفير قيصر
    encrypted = "Khoor Zruog"  # "Hello World" مع shift=3
    results = crypto.brute_force_caesar(encrypted)
    print("Caesar cipher results:")
    for shift, text, score in results[:3]:
        print(f"  Shift {shift}: {text} (Score: {score:.2f})")
    
    # اختبار XOR
    encrypted_xor = "secret"
    xor_results = crypto.brute_force_xor(encrypted_xor.encode())
    print("\nXOR results:")
    for key, text, score in xor_results[:3]:
        print(f"  Key {key}: {text} (Score: {score:.2f})")


if __name__ == "__main__":
    test_advanced_crypto()