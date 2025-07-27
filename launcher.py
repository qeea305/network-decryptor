#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
مشغل المشروع الرئيسي
Main Project Launcher
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import os


class ProjectLauncher:
    """مشغل المشروع"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🚀 مشغل أدوات فك التشفير")
        self.root.geometry("600x500")
        self.root.configure(bg='#2b2b2b')
        self.root.resizable(False, False)
        
        # وضع النافذة في المنتصف
        self.center_window()
        
        self.setup_ui()
    
    def center_window(self):
        """وضع النافذة في منتصف الشاشة"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_ui(self):
        """إعداد الواجهة"""
        # العنوان الرئيسي
        title_frame = tk.Frame(self.root, bg='#2b2b2b')
        title_frame.pack(fill=tk.X, pady=20)
        
        title_label = tk.Label(
            title_frame,
            text="🔓 مجموعة أدوات فك التشفير",
            font=('Arial', 20, 'bold'),
            fg='white',
            bg='#2b2b2b'
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Network Message Decryptor Tools Suite",
            font=('Arial', 12),
            fg='#cccccc',
            bg='#2b2b2b'
        )
        subtitle_label.pack(pady=(5, 0))
        
        # الأدوات المتاحة
        tools_frame = tk.Frame(self.root, bg='#2b2b2b')
        tools_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # قائمة الأدوات
        tools = [
            {
                'name': '🌐 أداة فك تشفير الشبكة',
                'description': 'التقاط وفك تشفير الرسائل من الشبكة مباشرة',
                'file': 'network_decryptor.py',
                'color': '#4CAF50'
            },
            {
                'name': '🔐 أداة التشفير التفاعلية',
                'description': 'تشفير وفك تشفير النصوص بطرق متعددة',
                'file': 'encryption_tool.py',
                'color': '#2196F3'
            },
            {
                'name': '🧪 اختبار العينات',
                'description': 'اختبار أنواع التشفير المختلفة مع عينات جاهزة',
                'file': 'examples.py',
                'color': '#FF9800'
            },
            {
                'name': '⚡ اختبار سريع',
                'description': 'فحص سريع للنظام والمكتبات المطلوبة',
                'file': 'quick_test.py',
                'color': '#9C27B0'
            },
            {
                'name': '🔧 اختبار التشفير المخصص',
                'description': 'اختبار خوارزميات التشفير المتقدمة والمخصصة',
                'file': 'custom_crypto.py',
                'color': '#607D8B'
            }
        ]
        
        for i, tool in enumerate(tools):
            self.create_tool_button(tools_frame, tool, i)
        
        # معلومات إضافية
        info_frame = tk.Frame(self.root, bg='#2b2b2b')
        info_frame.pack(fill=tk.X, padx=20, pady=10)
        
        info_text = """
💡 نصائح الاستخدام:
• تأكد من تشغيل أداة الشبكة بصلاحيات المدير
• استخدم الأداة فقط على الشبكات التي تملكها
• راجع دليل المستخدم للحصول على تعليمات مفصلة
        """
        
        info_label = tk.Label(
            info_frame,
            text=info_text,
            font=('Arial', 9),
            fg='#cccccc',
            bg='#2b2b2b',
            justify=tk.LEFT
        )
        info_label.pack(anchor=tk.W)
        
        # أزرار إضافية
        buttons_frame = tk.Frame(self.root, bg='#2b2b2b')
        buttons_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # زر دليل المستخدم
        guide_button = tk.Button(
            buttons_frame,
            text="📖 دليل المستخدم",
            command=self.open_user_guide,
            bg='#795548',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=15
        )
        guide_button.pack(side=tk.LEFT, padx=5)
        
        # زر README
        readme_button = tk.Button(
            buttons_frame,
            text="📄 README",
            command=self.open_readme,
            bg='#795548',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=15
        )
        readme_button.pack(side=tk.LEFT, padx=5)
        
        # زر الخروج
        exit_button = tk.Button(
            buttons_frame,
            text="❌ خروج",
            command=self.root.quit,
            bg='#f44336',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=15
        )
        exit_button.pack(side=tk.RIGHT, padx=5)
        
        # شريط الحالة
        self.status_bar = tk.Label(
            self.root,
            text="جاهز - اختر أداة للبدء",
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg='#1e1e1e',
            fg='white'
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_tool_button(self, parent, tool, index):
        """إنشاء زر أداة"""
        # إطار الأداة
        tool_frame = tk.Frame(parent, bg='#3c3c3c', relief=tk.RAISED, bd=1)
        tool_frame.pack(fill=tk.X, pady=5)
        
        # معلومات الأداة
        info_frame = tk.Frame(tool_frame, bg='#3c3c3c')
        info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        name_label = tk.Label(
            info_frame,
            text=tool['name'],
            font=('Arial', 12, 'bold'),
            fg='white',
            bg='#3c3c3c'
        )
        name_label.pack(anchor=tk.W)
        
        desc_label = tk.Label(
            info_frame,
            text=tool['description'],
            font=('Arial', 9),
            fg='#cccccc',
            bg='#3c3c3c',
            wraplength=400
        )
        desc_label.pack(anchor=tk.W, pady=(2, 0))
        
        # زر التشغيل
        run_button = tk.Button(
            tool_frame,
            text="▶️ تشغيل",
            command=lambda f=tool['file']: self.run_tool(f),
            bg=tool['color'],
            fg='white',
            font=('Arial', 10, 'bold'),
            width=10
        )
        run_button.pack(side=tk.RIGHT, padx=10, pady=10)
    
    def run_tool(self, filename):
        """تشغيل أداة"""
        if not os.path.exists(filename):
            messagebox.showerror("خطأ", f"الملف غير موجود: {filename}")
            return
        
        try:
            self.update_status(f"تشغيل {filename}...")
            
            # تشغيل الأداة في عملية منفصلة
            if sys.platform.startswith('win'):
                subprocess.Popen([sys.executable, filename], creationflags=subprocess.CREATE_NEW_CONSOLE)
            else:
                subprocess.Popen([sys.executable, filename])
            
            self.update_status(f"تم تشغيل {filename} بنجاح")
            
        except Exception as e:
            messagebox.showerror("خطأ", f"فشل في تشغيل {filename}:\n{str(e)}")
            self.update_status("فشل في التشغيل")
    
    def open_user_guide(self):
        """فتح دليل المستخدم"""
        try:
            if os.path.exists("USER_GUIDE.md"):
                if sys.platform.startswith('win'):
                    os.startfile("USER_GUIDE.md")
                else:
                    subprocess.run(['xdg-open', "USER_GUIDE.md"])
                self.update_status("تم فتح دليل المستخدم")
            else:
                messagebox.showwarning("تحذير", "ملف دليل المستخدم غير موجود")
        except Exception as e:
            messagebox.showerror("خطأ", f"فشل في فتح دليل المستخدم:\n{str(e)}")
    
    def open_readme(self):
        """فتح ملف README"""
        try:
            if os.path.exists("README.md"):
                if sys.platform.startswith('win'):
                    os.startfile("README.md")
                else:
                    subprocess.run(['xdg-open', "README.md"])
                self.update_status("تم فتح README")
            else:
                messagebox.showwarning("تحذير", "ملف README غير موجود")
        except Exception as e:
            messagebox.showerror("خطأ", f"فشل في فتح README:\n{str(e)}")
    
    def update_status(self, message):
        """تحديث شريط الحالة"""
        self.status_bar.config(text=message)
        self.root.update()
    
    def run(self):
        """تشغيل المشغل"""
        self.root.mainloop()


def main():
    """الدالة الرئيسية"""
    launcher = ProjectLauncher()
    launcher.run()


if __name__ == "__main__":
    main()