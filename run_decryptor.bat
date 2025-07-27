@echo off
echo ========================================
echo    أداة فك تشفير رسائل الشبكة
echo    Network Message Decryptor Tool
echo ========================================
echo.

echo تحقق من المتطلبات...
python --version >nul 2>&1
if errorlevel 1 (
    echo خطأ: Python غير مثبت!
    echo يرجى تثبيت Python أولاً
    pause
    exit /b 1
)

echo تثبيت المكتبات المطلوبة...
pip install -r requirements.txt

echo.
echo تشغيل الأداة...
echo ملاحظة: قد تحتاج صلاحيات المدير لالتقاط الشبكة
echo.

python network_decryptor.py

pause