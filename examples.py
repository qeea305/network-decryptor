#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أمثلة للاختبار
Testing Examples
"""

import base64
import binascii
import urllib.parse
from advanced_crypto import AdvancedDecryption


def generate_test_samples():
    """إنشاء عينات اختبار مشفرة"""
    
    # الرسائل الأصلية
    messages = [
        "Hello World!",
        "This is a secret message",
        "Password: admin123",
        "User login successful",
        "Database connection established",
        "Error: Access denied",
        "Welcome to the system",
        "Data transfer complete"
    ]
    
    samples = {}
    
    for i, message in enumerate(messages, 1):
        sample_name = f"sample_{i}"
        samples[sample_name] = {
            'original': message,
            'encrypted': {}
        }
        
        # Base64
        samples[sample_name]['encrypted']['base64'] = base64.b64encode(message.encode()).decode()
        
        # Hex
        samples[sample_name]['encrypted']['hex'] = message.encode().hex()
        
        # URL Encoding
        samples[sample_name]['encrypted']['url'] = urllib.parse.quote(message)
        
        # Caesar Cipher (shift 3)
        caesar_encrypted = ""
        for char in message:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                caesar_encrypted += chr((ord(char) - ascii_offset + 3) % 26 + ascii_offset)
            else:
                caesar_encrypted += char
        samples[sample_name]['encrypted']['caesar_3'] = caesar_encrypted
        
        # ROT13
        rot13_encrypted = ""
        for char in message:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                rot13_encrypted += chr((ord(char) - ascii_offset + 13) % 26 + ascii_offset)
            else:
                rot13_encrypted += char
        samples[sample_name]['encrypted']['rot13'] = rot13_encrypted
        
        # XOR with key "key"
        key = "key"
        xor_encrypted = ""
        for j, char in enumerate(message):
            xor_encrypted += chr(ord(char) ^ ord(key[j % len(key)]))
        samples[sample_name]['encrypted']['xor_key'] = xor_encrypted
        
        # Binary
        binary_encrypted = ' '.join(format(ord(char), '08b') for char in message)
        samples[sample_name]['encrypted']['binary'] = binary_encrypted
        
        # Atbash
        atbash_encrypted = ""
        for char in message:
            if char.isalpha():
                if char.isupper():
                    atbash_encrypted += chr(ord('Z') - (ord(char) - ord('A')))
                else:
                    atbash_encrypted += chr(ord('z') - (ord(char) - ord('a')))
            else:
                atbash_encrypted += char
        samples[sample_name]['encrypted']['atbash'] = atbash_encrypted
    
    return samples


def create_network_samples():
    """إنشاء عينات شبكة وهمية"""
    
    network_samples = [
        {
            'timestamp': '14:30:25',
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'protocol': 'TCP',
            'data': 'GET /login.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\nusername=admin&password=SGVsbG8xMjM='
        },
        {
            'timestamp': '14:30:26',
            'src_ip': '192.168.1.50',
            'dst_ip': '10.0.0.1',
            'protocol': 'UDP',
            'data': 'USER anonymous\r\nPASS guest@example.com'
        },
        {
            'timestamp': '14:30:27',
            'src_ip': '172.16.0.10',
            'dst_ip': '172.16.0.20',
            'protocol': 'TCP',
            'data': 'MAIL FROM: <test@example.com>\r\nRCPT TO: <user@domain.com>\r\nDATA\r\nSubject: VGVzdCBNZXNzYWdl\r\n\r\nSGVsbG8gV29ybGQh'
        },
        {
            'timestamp': '14:30:28',
            'src_ip': '192.168.1.200',
            'dst_ip': '8.8.8.8',
            'protocol': 'UDP',
            'data': 'DNS Query: example.com A'
        },
        {
            'timestamp': '14:30:29',
            'src_ip': '10.0.0.5',
            'dst_ip': '10.0.0.10',
            'protocol': 'TCP',
            'data': 'SSH-2.0-OpenSSH_7.4\r\nProtocol mismatch.\r\nlogin: root\r\npassword: dGVzdDEyMw=='
        }
    ]
    
    return network_samples


def create_jwt_samples():
    """إنشاء عينات JWT للاختبار"""
    
    # JWT مبسط للاختبار (لا يستخدم توقيع حقيقي)
    import json
    
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    
    payloads = [
        {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022
        },
        {
            "user": "admin",
            "role": "administrator",
            "exp": 1735689600
        },
        {
            "email": "user@example.com",
            "permissions": ["read", "write"],
            "iss": "example.com"
        }
    ]
    
    jwt_samples = []
    
    for payload in payloads:
        # ترميز الهيدر والحمولة
        header_encoded = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        # إنشاء JWT وهمي (بدون توقيع حقيقي)
        fake_signature = "fake_signature_for_testing"
        jwt_token = f"{header_encoded}.{payload_encoded}.{fake_signature}"
        
        jwt_samples.append({
            'token': jwt_token,
            'header': header,
            'payload': payload
        })
    
    return jwt_samples


def create_hash_samples():
    """إنشاء عينات هاش للاختبار"""
    import hashlib
    
    passwords = ["password", "123456", "admin", "secret", "test"]
    hash_samples = {}
    
    for password in passwords:
        hash_samples[password] = {
            'md5': hashlib.md5(password.encode()).hexdigest(),
            'sha1': hashlib.sha1(password.encode()).hexdigest(),
            'sha256': hashlib.sha256(password.encode()).hexdigest()
        }
    
    return hash_samples


def test_all_samples():
    """اختبار جميع العينات"""
    print("🧪 اختبار جميع العينات")
    print("=" * 50)
    
    # إنشاء محرك فك التشفير
    crypto = AdvancedDecryption()
    
    # اختبار العينات المشفرة
    print("\n📝 اختبار العينات المشفرة:")
    samples = generate_test_samples()
    
    for sample_name, sample_data in list(samples.items())[:3]:  # أول 3 عينات فقط
        print(f"\n🔍 {sample_name}:")
        print(f"الأصلي: {sample_data['original']}")
        
        for method, encrypted in sample_data['encrypted'].items():
            print(f"\n  {method}: {encrypted[:50]}{'...' if len(encrypted) > 50 else ''}")
            
            # محاولة فك التشفير التلقائي
            results = crypto.analyze_all_methods(encrypted)
            if results:
                best_result = list(results.items())[0]
                method_name, (decrypted, score) = best_result
                success = "✅" if sample_data['original'].lower() in decrypted.lower() else "❌"
                print(f"    أفضل نتيجة: {method_name} - {decrypted[:30]}... (نتيجة: {score:.1f}) {success}")
    
    # اختبار عينات الشبكة
    print(f"\n🌐 اختبار عينات الشبكة:")
    network_samples = create_network_samples()
    
    for sample in network_samples[:2]:  # أول عينتين فقط
        print(f"\n📦 {sample['src_ip']} → {sample['dst_ip']} ({sample['protocol']}):")
        print(f"البيانات: {sample['data'][:100]}{'...' if len(sample['data']) > 100 else ''}")
        
        # البحث عن بيانات مشفرة في العينة
        results = crypto.analyze_all_methods(sample['data'])
        if results:
            print("  🔓 بيانات مشفرة محتملة:")
            for method_name, (decrypted, score) in list(results.items())[:2]:
                print(f"    {method_name}: {decrypted[:50]}... (نتيجة: {score:.1f})")
    
    # اختبار JWT
    print(f"\n🎫 اختبار JWT:")
    jwt_samples = create_jwt_samples()
    
    for i, jwt_sample in enumerate(jwt_samples[:2], 1):
        print(f"\nJWT {i}:")
        print(f"Token: {jwt_sample['token'][:50]}...")
        print(f"Header: {jwt_sample['header']}")
        print(f"Payload: {jwt_sample['payload']}")
    
    # اختبار الهاش
    print(f"\n🔐 اختبار الهاش:")
    hash_samples = create_hash_samples()
    
    for password, hashes in list(hash_samples.items())[:3]:
        print(f"\nكلمة المرور: {password}")
        for hash_type, hash_value in hashes.items():
            print(f"  {hash_type.upper()}: {hash_value}")


def save_samples_to_file():
    """حفظ العينات في ملف للاستخدام اللاحق"""
    import json
    
    all_samples = {
        'encrypted_samples': generate_test_samples(),
        'network_samples': create_network_samples(),
        'jwt_samples': create_jwt_samples(),
        'hash_samples': create_hash_samples()
    }
    
    with open('test_samples.json', 'w', encoding='utf-8') as f:
        json.dump(all_samples, f, indent=2, ensure_ascii=False)
    
    print("💾 تم حفظ جميع العينات في ملف test_samples.json")


def interactive_test():
    """اختبار تفاعلي"""
    print("🎮 اختبار تفاعلي")
    print("=" * 30)
    
    crypto = AdvancedDecryption()
    
    while True:
        print("\nاختر نوع الاختبار:")
        print("1. اختبار نص مشفر")
        print("2. عرض عينات جاهزة")
        print("3. اختبار JWT")
        print("4. خروج")
        
        choice = input("\nاختيارك (1-4): ").strip()
        
        if choice == '1':
            encrypted_text = input("أدخل النص المشفر: ").strip()
            if encrypted_text:
                print("\n🔍 تحليل النص...")
                results = crypto.analyze_all_methods(encrypted_text)
                
                if results:
                    print("✅ النتائج المحتملة:")
                    for method_name, (decrypted, score) in results.items():
                        print(f"  {method_name}: {decrypted} (نتيجة: {score:.1f})")
                else:
                    print("❌ لم يتم العثور على نتائج مفهومة")
        
        elif choice == '2':
            samples = generate_test_samples()
            sample_names = list(samples.keys())
            
            print("\nالعينات المتاحة:")
            for i, name in enumerate(sample_names, 1):
                print(f"{i}. {samples[name]['original']}")
            
            try:
                sample_choice = int(input(f"\nاختر عينة (1-{len(sample_names)}): ")) - 1
                if 0 <= sample_choice < len(sample_names):
                    sample_name = sample_names[sample_choice]
                    sample = samples[sample_name]
                    
                    print(f"\n📝 العينة: {sample['original']}")
                    print("الأشكال المشفرة:")
                    
                    for method, encrypted in sample['encrypted'].items():
                        print(f"  {method}: {encrypted}")
                else:
                    print("❌ اختيار غير صحيح")
            except ValueError:
                print("❌ يرجى إدخال رقم صحيح")
        
        elif choice == '3':
            jwt_samples = create_jwt_samples()
            
            print("\nعينات JWT:")
            for i, jwt_sample in enumerate(jwt_samples, 1):
                print(f"\n{i}. Token: {jwt_sample['token']}")
                print(f"   Header: {jwt_sample['header']}")
                print(f"   Payload: {jwt_sample['payload']}")
        
        elif choice == '4':
            print("👋 وداعاً!")
            break
        
        else:
            print("❌ اختيار غير صحيح")


if __name__ == "__main__":
    print("🧪 مولد عينات الاختبار")
    print("=" * 40)
    
    print("\nاختر وضع التشغيل:")
    print("1. اختبار جميع العينات")
    print("2. حفظ العينات في ملف")
    print("3. اختبار تفاعلي")
    
    choice = input("\nاختيارك (1-3): ").strip()
    
    if choice == '1':
        test_all_samples()
    elif choice == '2':
        save_samples_to_file()
    elif choice == '3':
        interactive_test()
    else:
        print("❌ اختيار غير صحيح")
        test_all_samples()  # تشغيل الاختبار الافتراضي