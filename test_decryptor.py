#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار أداة فك التشفير
Test Network Decryptor Tool
"""

import base64
import binascii
from advanced_crypto import AdvancedDecryption


def create_test_data():
    """إنشاء بيانات اختبار مشفرة"""
    test_message = "Hello World! This is a secret message."
    
    test_data = {}
    
    # Base64
    test_data['base64'] = base64.b64encode(test_message.encode()).decode()
    
    # Hex
    test_data['hex'] = test_message.encode().hex()
    
    # Caesar cipher (shift 3)
    caesar_encrypted = ""
    for char in test_message:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            caesar_encrypted += chr((ord(char) - ascii_offset + 3) % 26 + ascii_offset)
        else:
            caesar_encrypted += char
    test_data['caesar'] = caesar_encrypted
    
    # ROT13
    rot13_encrypted = ""
    for char in test_message:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            rot13_encrypted += chr((ord(char) - ascii_offset + 13) % 26 + ascii_offset)
        else:
            rot13_encrypted += char
    test_data['rot13'] = rot13_encrypted
    
    # XOR with key "key"
    key = "key"
    xor_encrypted = ""
    for i, char in enumerate(test_message):
        xor_encrypted += chr(ord(char) ^ ord(key[i % len(key)]))
    test_data['xor'] = xor_encrypted
    
    # Binary
    binary_encrypted = ' '.join(format(ord(char), '08b') for char in test_message)
    test_data['binary'] = binary_encrypted
    
    # Morse code
    morse_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', ' ': '/'
    }
    
    morse_encrypted = ' '.join(morse_dict.get(char.upper(), char) for char in test_message)
    test_data['morse'] = morse_encrypted
    
    return test_data, test_message


def test_decryption_methods():
    """اختبار طرق فك التشفير"""
    print("🔓 اختبار أداة فك التشفير")
    print("=" * 50)
    
    # إنشاء بيانات الاختبار
    test_data, original_message = create_test_data()
    
    print(f"الرسالة الأصلية: {original_message}")
    print("-" * 50)
    
    # إنشاء محرك فك التشفير
    crypto = AdvancedDecryption()
    
    # اختبار كل طريقة
    for method, encrypted_data in test_data.items():
        print(f"\n🔐 اختبار {method.upper()}:")
        print(f"البيانات المشفرة: {encrypted_data[:50]}{'...' if len(encrypted_data) > 50 else ''}")
        
        # محاولة فك التشفير التلقائي
        results = crypto.analyze_all_methods(encrypted_data)
        
        if results:
            print("✅ نتائج فك التشفير:")
            for method_name, (decrypted, score) in list(results.items())[:3]:
                print(f"  {method_name}: {decrypted[:50]}{'...' if len(decrypted) > 50 else ''} (نتيجة: {score:.2f})")
        else:
            print("❌ لم يتم فك التشفير بنجاح")
    
    print("\n" + "=" * 50)
    print("انتهى الاختبار!")


def test_frequency_analysis():
    """اختبار تحليل التكرار"""
    print("\n📊 اختبار تحليل التكرار")
    print("-" * 30)
    
    crypto = AdvancedDecryption()
    
    # نص إنجليزي عادي
    english_text = "The quick brown fox jumps over the lazy dog"
    freq = crypto.frequency_analysis(english_text)
    
    print("تكرار الأحرف في النص الإنجليزي:")
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    for char, percentage in sorted_freq[:10]:
        if char.isalpha():
            print(f"  {char}: {percentage:.2f}%")


def test_caesar_brute_force():
    """اختبار كسر تشفير قيصر"""
    print("\n⚔️ اختبار كسر تشفير قيصر")
    print("-" * 30)
    
    crypto = AdvancedDecryption()
    
    # تشفير رسالة بقيصر
    message = "ATTACK AT DAWN"
    shift = 7
    
    encrypted = ""
    for char in message:
        if char.isalpha():
            encrypted += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            encrypted += char
    
    print(f"الرسالة الأصلية: {message}")
    print(f"مشفرة بإزاحة {shift}: {encrypted}")
    
    # محاولة كسر التشفير
    results = crypto.brute_force_caesar(encrypted)
    
    print("أفضل 5 نتائج:")
    for shift_try, decrypted, score in results[:5]:
        print(f"  إزاحة {shift_try}: {decrypted} (نتيجة: {score:.2f})")


def test_xor_brute_force():
    """اختبار كسر XOR"""
    print("\n⚔️ اختبار كسر XOR")
    print("-" * 30)
    
    crypto = AdvancedDecryption()
    
    # تشفير رسالة بـ XOR
    message = "SECRET MESSAGE"
    key = "ABC"
    
    encrypted_bytes = bytearray()
    for i, char in enumerate(message):
        encrypted_bytes.append(ord(char) ^ ord(key[i % len(key)]))
    
    print(f"الرسالة الأصلية: {message}")
    print(f"المفتاح: {key}")
    print(f"مشفرة: {encrypted_bytes.hex()}")
    
    # محاولة كسر التشفير
    results = crypto.brute_force_xor(encrypted_bytes)
    
    print("أفضل 3 نتائج:")
    for key_found, decrypted, score in results[:3]:
        print(f"  مفتاح {key_found}: {decrypted} (نتيجة: {score:.2f})")


if __name__ == "__main__":
    # تشغيل جميع الاختبارات
    test_decryption_methods()
    test_frequency_analysis()
    test_caesar_brute_force()
    test_xor_brute_force()
    
    print("\n🎉 تم الانتهاء من جميع الاختبارات!")
    print("يمكنك الآن تشغيل الأداة الرئيسية: python network_decryptor.py")