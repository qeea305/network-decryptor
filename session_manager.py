#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
مدير الجلسات
Session Manager
"""

import json
import os
import pickle
import gzip
from datetime import datetime
import hashlib


class SessionManager:
    """مدير الجلسات لحفظ وتحميل البيانات"""
    
    def __init__(self, sessions_dir="sessions"):
        self.sessions_dir = sessions_dir
        self.ensure_sessions_dir()
    
    def ensure_sessions_dir(self):
        """التأكد من وجود مجلد الجلسات"""
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir)
    
    def save_session(self, session_data, session_name=None):
        """حفظ جلسة العمل"""
        if not session_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            session_name = f"session_{timestamp}"
        
        # إعداد بيانات الجلسة
        session_info = {
            'name': session_name,
            'timestamp': datetime.now().isoformat(),
            'version': '1.0',
            'data': session_data
        }
        
        # حفظ كملف JSON مضغوط
        session_file = os.path.join(self.sessions_dir, f"{session_name}.json.gz")
        
        try:
            with gzip.open(session_file, 'wt', encoding='utf-8') as f:
                json.dump(session_info, f, indent=2, ensure_ascii=False)
            
            return session_file
        except Exception as e:
            raise Exception(f"خطأ في حفظ الجلسة: {str(e)}")
    
    def load_session(self, session_file):
        """تحميل جلسة العمل"""
        try:
            if session_file.endswith('.gz'):
                with gzip.open(session_file, 'rt', encoding='utf-8') as f:
                    session_info = json.load(f)
            else:
                with open(session_file, 'r', encoding='utf-8') as f:
                    session_info = json.load(f)
            
            return session_info
        except Exception as e:
            raise Exception(f"خطأ في تحميل الجلسة: {str(e)}")
    
    def list_sessions(self):
        """قائمة الجلسات المحفوظة"""
        sessions = []
        
        for filename in os.listdir(self.sessions_dir):
            if filename.endswith('.json') or filename.endswith('.json.gz'):
                filepath = os.path.join(self.sessions_dir, filename)
                try:
                    session_info = self.load_session(filepath)
                    sessions.append({
                        'filename': filename,
                        'filepath': filepath,
                        'name': session_info.get('name', filename),
                        'timestamp': session_info.get('timestamp', 'غير معروف'),
                        'size': os.path.getsize(filepath)
                    })
                except:
                    continue
        
        # ترتيب حسب التاريخ
        sessions.sort(key=lambda x: x['timestamp'], reverse=True)
        return sessions
    
    def delete_session(self, session_file):
        """حذف جلسة"""
        try:
            os.remove(session_file)
            return True
        except Exception as e:
            raise Exception(f"خطأ في حذف الجلسة: {str(e)}")
    
    def export_session(self, session_file, export_format='json'):
        """تصدير الجلسة بصيغة مختلفة"""
        session_info = self.load_session(session_file)
        
        base_name = os.path.splitext(os.path.basename(session_file))[0]
        if base_name.endswith('.json'):
            base_name = os.path.splitext(base_name)[0]
        
        if export_format == 'json':
            export_file = os.path.join(self.sessions_dir, f"{base_name}_export.json")
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(session_info, f, indent=2, ensure_ascii=False)
        
        elif export_format == 'csv':
            import csv
            export_file = os.path.join(self.sessions_dir, f"{base_name}_export.csv")
            
            # استخراج بيانات الحزم للـ CSV
            packets_data = session_info.get('data', {}).get('packets', [])
            
            with open(export_file, 'w', newline='', encoding='utf-8') as f:
                if packets_data:
                    writer = csv.DictWriter(f, fieldnames=packets_data[0].keys())
                    writer.writeheader()
                    writer.writerows(packets_data)
        
        elif export_format == 'txt':
            export_file = os.path.join(self.sessions_dir, f"{base_name}_export.txt")
            
            with open(export_file, 'w', encoding='utf-8') as f:
                f.write(f"جلسة: {session_info.get('name', 'غير معروف')}\n")
                f.write(f"التاريخ: {session_info.get('timestamp', 'غير معروف')}\n")
                f.write("=" * 50 + "\n\n")
                
                packets_data = session_info.get('data', {}).get('packets', [])
                for i, packet in enumerate(packets_data, 1):
                    f.write(f"الحزمة {i}:\n")
                    for key, value in packet.items():
                        f.write(f"  {key}: {value}\n")
                    f.write("\n")
        
        return export_file
    
    def get_session_stats(self, session_file):
        """إحصائيات الجلسة"""
        session_info = self.load_session(session_file)
        data = session_info.get('data', {})
        
        stats = {
            'name': session_info.get('name', 'غير معروف'),
            'timestamp': session_info.get('timestamp', 'غير معروف'),
            'file_size': os.path.getsize(session_file),
            'total_packets': len(data.get('packets', [])),
            'decrypted_messages': len(data.get('decrypted_messages', [])),
            'protocols': {},
            'suspicious_count': 0
        }
        
        # تحليل البروتوكولات
        for packet in data.get('packets', []):
            protocol = packet.get('protocol', 'Unknown')
            stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1
            
            if packet.get('suspicious', False):
                stats['suspicious_count'] += 1
        
        return stats


class DataExporter:
    """مصدر البيانات"""
    
    def __init__(self):
        self.supported_formats = ['json', 'csv', 'xml', 'html', 'txt']
    
    def export_packets(self, packets_data, filename, format_type='json'):
        """تصدير بيانات الحزم"""
        if format_type not in self.supported_formats:
            raise ValueError(f"صيغة غير مدعومة: {format_type}")
        
        if format_type == 'json':
            return self._export_json(packets_data, filename)
        elif format_type == 'csv':
            return self._export_csv(packets_data, filename)
        elif format_type == 'xml':
            return self._export_xml(packets_data, filename)
        elif format_type == 'html':
            return self._export_html(packets_data, filename)
        elif format_type == 'txt':
            return self._export_txt(packets_data, filename)
    
    def _export_json(self, data, filename):
        """تصدير JSON"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filename
    
    def _export_csv(self, data, filename):
        """تصدير CSV"""
        import csv
        
        if not data:
            return filename
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        
        return filename
    
    def _export_xml(self, data, filename):
        """تصدير XML"""
        import xml.etree.ElementTree as ET
        
        root = ET.Element("packets")
        
        for packet in data:
            packet_elem = ET.SubElement(root, "packet")
            for key, value in packet.items():
                elem = ET.SubElement(packet_elem, key)
                elem.text = str(value)
        
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)
        
        return filename
    
    def _export_html(self, data, filename):
        """تصدير HTML"""
        html_content = """
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <title>تقرير تحليل الحزم</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: right; }
        th { background-color: #f2f2f2; }
        .header { background-color: #4CAF50; color: white; padding: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔓 تقرير تحليل الحزم</h1>
        <p>تم إنشاؤه في: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
    </div>
    
    <h2>إجمالي الحزم: """ + str(len(data)) + """</h2>
    
    <table>
        <thead>
            <tr>
"""
        
        if data:
            # إضافة رؤوس الأعمدة
            for key in data[0].keys():
                html_content += f"                <th>{key}</th>\n"
            
            html_content += """            </tr>
        </thead>
        <tbody>
"""
            
            # إضافة البيانات
            for packet in data:
                html_content += "            <tr>\n"
                for value in packet.values():
                    html_content += f"                <td>{str(value)[:100]}{'...' if len(str(value)) > 100 else ''}</td>\n"
                html_content += "            </tr>\n"
        
        html_content += """        </tbody>
    </table>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename
    
    def _export_txt(self, data, filename):
        """تصدير TXT"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("🔓 تقرير تحليل الحزم\n")
            f.write("=" * 50 + "\n")
            f.write(f"تاريخ الإنشاء: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"إجمالي الحزم: {len(data)}\n")
            f.write("=" * 50 + "\n\n")
            
            for i, packet in enumerate(data, 1):
                f.write(f"الحزمة {i}:\n")
                f.write("-" * 30 + "\n")
                for key, value in packet.items():
                    f.write(f"{key}: {str(value)[:200]}{'...' if len(str(value)) > 200 else ''}\n")
                f.write("\n")
        
        return filename


def test_session_manager():
    """اختبار مدير الجلسات"""
    print("💾 اختبار مدير الجلسات")
    print("=" * 30)
    
    # إنشاء مدير الجلسات
    session_manager = SessionManager()
    
    # بيانات اختبار
    test_data = {
        'packets': [
            {
                'timestamp': '12:34:56',
                'src_ip': '192.168.1.1',
                'dst_ip': '192.168.1.2',
                'protocol': 'TCP',
                'data': 'Hello World'
            },
            {
                'timestamp': '12:34:57',
                'src_ip': '192.168.1.2',
                'dst_ip': '192.168.1.1',
                'protocol': 'UDP',
                'data': 'Response'
            }
        ],
        'decrypted_messages': [
            {
                'original': 'SGVsbG8=',
                'decrypted': 'Hello',
                'method': 'base64'
            }
        ]
    }
    
    # حفظ الجلسة
    try:
        session_file = session_manager.save_session(test_data, "test_session")
        print(f"✅ تم حفظ الجلسة: {session_file}")
        
        # تحميل الجلسة
        loaded_session = session_manager.load_session(session_file)
        print(f"✅ تم تحميل الجلسة: {loaded_session['name']}")
        
        # إحصائيات الجلسة
        stats = session_manager.get_session_stats(session_file)
        print(f"📊 إحصائيات الجلسة:")
        print(f"  - إجمالي الحزم: {stats['total_packets']}")
        print(f"  - الرسائل المفكوكة: {stats['decrypted_messages']}")
        print(f"  - البروتوكولات: {stats['protocols']}")
        
        # قائمة الجلسات
        sessions = session_manager.list_sessions()
        print(f"📋 الجلسات المحفوظة: {len(sessions)}")
        
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")


if __name__ == "__main__":
    test_session_manager()