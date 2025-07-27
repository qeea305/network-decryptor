#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار سريع للأداة
Quick Test for the Tool
"""

import sys
import os

def test_imports():
    """اختبار استيراد المكتبات"""
    print("🔍 اختبار استيراد المكتبات...")
    
    try:
        import tkinter as tk
        print("✅ tkinter - متوفر")
    except ImportError:
        print("❌ tkinter - غير متوفر")
        return False
    
    try:
        import scapy
        print("✅ scapy - متوفر")
    except ImportError:
        print("❌ scapy - غير متوفر (سيتم تعطيل التقاط الشبكة)")
    
    try:
        import cryptography
        print("✅ cryptography - متوفر")
    except ImportError:
        print("❌ cryptography - غير متوفر (سيتم تعطيل بعض ميزات التشفير)")
    
    try:
        from Crypto.Cipher import AES
        print("✅ pycryptodome - متوفر")
    except ImportError:
        print("❌ pycryptodome - غير متوفر (سيتم تعطيل بعض ميزات التشفير)")
    
    return True

def test_modules():
    """اختبار الوحدات المحلية"""
    print("\n🧩 اختبار الوحدات المحلية...")
    
    try:
        from advanced_crypto import AdvancedDecryption
        crypto = AdvancedDecryption()
        print("✅ advanced_crypto - يعمل بشكل صحيح")
        
        # اختبار سريع
        result = crypto.decode_base64("SGVsbG8=")
        if result == "Hello":
            print("  ✅ فك Base64 يعمل")
        else:
            print("  ❌ مشكلة في فك Base64")
            
    except Exception as e:
        print(f"❌ advanced_crypto - خطأ: {str(e)}")
    
    try:
        from session_manager import SessionManager
        session_mgr = SessionManager()
        print("✅ session_manager - يعمل بشكل صحيح")
    except Exception as e:
        print(f"❌ session_manager - خطأ: {str(e)}")
    
    try:
        from packet_analyzer import PacketAnalyzer
        analyzer = PacketAnalyzer()
        print("✅ packet_analyzer - يعمل بشكل صحيح")
    except Exception as e:
        print(f"❌ packet_analyzer - خطأ: {str(e)}")

def test_decryption():
    """اختبار سريع لفك التشفير"""
    print("\n🔓 اختبار سريع لفك التشفير...")
    
    try:
        from advanced_crypto import AdvancedDecryption
        crypto = AdvancedDecryption()
        
        # اختبارات سريعة
        tests = [
            ("SGVsbG8gV29ybGQ=", "base64", "Hello World"),
            ("48656c6c6f", "hex", "Hello"),
            ("Khoor", "caesar", "Hello"),
            ("Uryyb", "rot13", "Hello")
        ]
        
        for encrypted, method, expected in tests:
            try:
                if method == "base64":
                    result = crypto.decode_base64(encrypted)
                elif method == "hex":
                    result = crypto.decode_hex(encrypted)
                elif method == "caesar":
                    result = crypto.decode_caesar(encrypted, 3)
                elif method == "rot13":
                    result = crypto.decode_rot13(encrypted)
                
                if expected.lower() in result.lower():
                    print(f"  ✅ {method.upper()}: {encrypted} → {result}")
                else:
                    print(f"  ❌ {method.upper()}: {encrypted} → {result} (متوقع: {expected})")
                    
            except Exception as e:
                print(f"  ❌ {method.upper()}: خطأ - {str(e)}")
                
    except Exception as e:
        print(f"❌ خطأ في اختبار فك التشفير: {str(e)}")

def test_gui():
    """اختبار الواجهة الرسومية"""
    print("\n🖥️ اختبار الواجهة الرسومية...")
    
    try:
        import tkinter as tk
        
        # إنشاء نافذة اختبار
        root = tk.Tk()
        root.title("اختبار")
        root.geometry("300x200")
        
        label = tk.Label(root, text="اختبار الواجهة الرسومية", font=('Arial', 12))
        label.pack(pady=50)
        
        button = tk.Button(root, text="إغلاق", command=root.destroy)
        button.pack()
        
        print("✅ الواجهة الرسومية تعمل بشكل صحيح")
        print("  (سيتم إغلاق النافذة تلقائياً)")
        
        # إغلاق تلقائي بعد ثانية واحدة
        root.after(1000, root.destroy)
        root.mainloop()
        
    except Exception as e:
        print(f"❌ مشكلة في الواجهة الرسومية: {str(e)}")

def test_files():
    """اختبار وجود الملفات المطلوبة"""
    print("\n📁 اختبار وجود الملفات...")
    
    required_files = [
        "network_decryptor.py",
        "advanced_crypto.py",
        "session_manager.py",
        "packet_analyzer.py",
        "requirements.txt",
        "config.json"
    ]
    
    for filename in required_files:
        if os.path.exists(filename):
            print(f"✅ {filename}")
        else:
            print(f"❌ {filename} - مفقود")

def run_main_app():
    """تشغيل التطبيق الرئيسي"""
    print("\n🚀 تشغيل التطبيق الرئيسي...")
    
    try:
        from network_decryptor import NetworkDecryptorGUI
        
        print("✅ تم تحميل التطبيق بنجاح")
        print("🎯 بدء تشغيل الواجهة الرسومية...")
        
        app = NetworkDecryptorGUI()
        app.run()
        
    except KeyboardInterrupt:
        print("\n👋 تم إيقاف التطبيق بواسطة المستخدم")
    except Exception as e:
        print(f"❌ خطأ في تشغيل التطبيق: {str(e)}")
        print("\nتفاصيل الخطأ:")
        import traceback
        traceback.print_exc()

def main():
    """الدالة الرئيسية"""
    print("🔧 اختبار سريع لأداة فك تشفير رسائل الشبكة")
    print("=" * 60)
    
    # اختبار المكتبات
    if not test_imports():
        print("\n❌ فشل في اختبار المكتبات الأساسية")
        return
    
    # اختبار الوحدات
    test_modules()
    
    # اختبار فك التشفير
    test_decryption()
    
    # اختبار الملفات
    test_files()
    
    # اختبار الواجهة الرسومية
    test_gui()
    
    print("\n" + "=" * 60)
    print("✅ انتهى الاختبار السريع!")
    
    # سؤال المستخدم عن تشغيل التطبيق
    try:
        choice = input("\nهل تريد تشغيل التطبيق الرئيسي؟ (y/n): ").strip().lower()
        if choice in ['y', 'yes', 'نعم', '1']:
            run_main_app()
        else:
            print("👋 شكراً لك!")
    except KeyboardInterrupt:
        print("\n👋 وداعاً!")

if __name__ == "__main__":
    main()