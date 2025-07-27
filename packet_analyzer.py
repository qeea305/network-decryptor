#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
محلل الحزم المتقدم
Advanced Packet Analyzer
"""

import re
import json
import base64
from urllib.parse import unquote
from collections import defaultdict
import hashlib

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketAnalyzer:
    """محلل الحزم المتقدم"""
    
    def __init__(self):
        self.protocols = {
            'HTTP': self.analyze_http,
            'HTTPS': self.analyze_https,
            'FTP': self.analyze_ftp,
            'SMTP': self.analyze_smtp,
            'DNS': self.analyze_dns,
            'TELNET': self.analyze_telnet
        }
        
        # أنماط البيانات المشفرة الشائعة
        self.crypto_patterns = {
            'base64': r'^[A-Za-z0-9+/]*={0,2}$',
            'hex': r'^[0-9a-fA-F]+$',
            'jwt': r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$',
            'hash_md5': r'^[a-f0-9]{32}$',
            'hash_sha1': r'^[a-f0-9]{40}$',
            'hash_sha256': r'^[a-f0-9]{64}$',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        }
    
    def analyze_packet(self, packet):
        """تحليل شامل للحزمة"""
        analysis = {
            'basic_info': self.get_basic_info(packet),
            'protocol_analysis': {},
            'crypto_analysis': {},
            'suspicious_patterns': [],
            'extracted_data': []
        }
        
        # تحليل البروتوكول
        if Raw in packet:
            raw_data = packet[Raw].load
            text_data = self.extract_text_data(raw_data)
            
            # تحديد البروتوكول وتحليله
            protocol = self.identify_protocol(packet, text_data)
            if protocol in self.protocols:
                analysis['protocol_analysis'] = self.protocols[protocol](text_data, packet)
            
            # تحليل التشفير
            analysis['crypto_analysis'] = self.analyze_crypto_patterns(text_data)
            
            # البحث عن أنماط مشبوهة
            analysis['suspicious_patterns'] = self.find_suspicious_patterns(text_data)
            
            # استخراج البيانات المهمة
            analysis['extracted_data'] = self.extract_important_data(text_data)
        
        return analysis
    
    def get_basic_info(self, packet):
        """استخراج المعلومات الأساسية"""
        info = {
            'timestamp': packet.time if hasattr(packet, 'time') else None,
            'size': len(packet),
            'layers': [layer.name for layer in packet.layers()]
        }
        
        if IP in packet:
            info.update({
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto
            })
        
        if TCP in packet:
            info.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': packet[TCP].flags
            })
        elif UDP in packet:
            info.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
        
        return info
    
    def extract_text_data(self, raw_data):
        """استخراج البيانات النصية"""
        try:
            return raw_data.decode('utf-8', errors='ignore')
        except:
            return str(raw_data)
    
    def identify_protocol(self, packet, text_data):
        """تحديد البروتوكول"""
        if TCP in packet:
            port = packet[TCP].dport
            
            # HTTP
            if port == 80 or 'HTTP/' in text_data:
                return 'HTTP'
            # HTTPS
            elif port == 443:
                return 'HTTPS'
            # FTP
            elif port == 21 or port == 20:
                return 'FTP'
            # SMTP
            elif port == 25 or port == 587:
                return 'SMTP'
            # TELNET
            elif port == 23:
                return 'TELNET'
        
        elif UDP in packet:
            port = packet[UDP].dport
            # DNS
            if port == 53:
                return 'DNS'
        
        return 'UNKNOWN'
    
    def analyze_http(self, data, packet):
        """تحليل HTTP"""
        analysis = {
            'method': None,
            'url': None,
            'headers': {},
            'body': None,
            'cookies': {},
            'forms': []
        }
        
        lines = data.split('\n')
        if lines:
            # استخراج الطريقة والرابط
            first_line = lines[0].strip()
            if ' ' in first_line:
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    analysis['method'] = parts[0]
                    analysis['url'] = parts[1]
            
            # استخراج الهيدرز
            in_headers = True
            body_start = 0
            
            for i, line in enumerate(lines[1:], 1):
                line = line.strip()
                if not line and in_headers:
                    in_headers = False
                    body_start = i + 1
                    continue
                
                if in_headers and ':' in line:
                    key, value = line.split(':', 1)
                    analysis['headers'][key.strip()] = value.strip()
                    
                    # استخراج الكوكيز
                    if key.strip().lower() == 'cookie':
                        cookies = value.strip().split(';')
                        for cookie in cookies:
                            if '=' in cookie:
                                name, val = cookie.split('=', 1)
                                analysis['cookies'][name.strip()] = val.strip()
            
            # استخراج الجسم
            if body_start < len(lines):
                analysis['body'] = '\n'.join(lines[body_start:])
                
                # البحث عن النماذج
                analysis['forms'] = self.extract_forms(analysis['body'])
        
        return analysis
    
    def analyze_https(self, data, packet):
        """تحليل HTTPS (محدود بسبب التشفير)"""
        return {
            'encrypted': True,
            'tls_version': self.detect_tls_version(data),
            'cipher_suite': None,
            'certificate_info': None
        }
    
    def analyze_ftp(self, data, packet):
        """تحليل FTP"""
        analysis = {
            'commands': [],
            'responses': [],
            'credentials': None
        }
        
        lines = data.split('\n')
        for line in lines:
            line = line.strip()
            if line:
                # أوامر FTP
                if line.startswith(('USER ', 'PASS ', 'CWD ', 'LIST', 'RETR ', 'STOR ')):
                    analysis['commands'].append(line)
                    
                    # استخراج بيانات الاعتماد
                    if line.startswith('USER '):
                        username = line[5:].strip()
                        analysis['credentials'] = {'username': username}
                    elif line.startswith('PASS ') and analysis['credentials']:
                        password = line[5:].strip()
                        analysis['credentials']['password'] = password
                
                # ردود FTP
                elif re.match(r'^\d{3}', line):
                    analysis['responses'].append(line)
        
        return analysis
    
    def analyze_smtp(self, data, packet):
        """تحليل SMTP"""
        analysis = {
            'commands': [],
            'email_data': {},
            'attachments': []
        }
        
        lines = data.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if line:
                # أوامر SMTP
                if line.startswith(('HELO ', 'EHLO ', 'MAIL FROM:', 'RCPT TO:', 'DATA')):
                    analysis['commands'].append(line)
                
                # بيانات الإيميل
                elif line.startswith(('From:', 'To:', 'Subject:', 'Date:')):
                    key, value = line.split(':', 1)
                    analysis['email_data'][key.strip()] = value.strip()
        
        return analysis
    
    def analyze_dns(self, data, packet):
        """تحليل DNS"""
        analysis = {
            'queries': [],
            'responses': [],
            'record_types': []
        }
        
        if DNS in packet:
            dns_packet = packet[DNS]
            
            # الاستعلامات
            if dns_packet.qd:
                for query in dns_packet.qd:
                    analysis['queries'].append({
                        'name': query.qname.decode() if hasattr(query.qname, 'decode') else str(query.qname),
                        'type': query.qtype,
                        'class': query.qclass
                    })
            
            # الردود
            if dns_packet.an:
                for answer in dns_packet.an:
                    analysis['responses'].append({
                        'name': answer.rrname.decode() if hasattr(answer.rrname, 'decode') else str(answer.rrname),
                        'type': answer.type,
                        'data': str(answer.rdata)
                    })
        
        return analysis
    
    def analyze_telnet(self, data, packet):
        """تحليل TELNET"""
        return {
            'data': data,
            'potential_credentials': self.extract_credentials(data),
            'commands': self.extract_commands(data)
        }
    
    def analyze_crypto_patterns(self, data):
        """تحليل أنماط التشفير"""
        patterns_found = {}
        
        for pattern_name, pattern_regex in self.crypto_patterns.items():
            matches = re.findall(pattern_regex, data, re.MULTILINE)
            if matches:
                patterns_found[pattern_name] = matches
        
        # تحليل JWT
        jwt_tokens = re.findall(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', data)
        if jwt_tokens:
            patterns_found['jwt_analysis'] = []
            for token in jwt_tokens:
                try:
                    header, payload, signature = token.split('.')
                    # فك ترميز الهيدر والحمولة
                    header_decoded = base64.b64decode(header + '==').decode('utf-8', errors='ignore')
                    payload_decoded = base64.b64decode(payload + '==').decode('utf-8', errors='ignore')
                    
                    patterns_found['jwt_analysis'].append({
                        'token': token,
                        'header': header_decoded,
                        'payload': payload_decoded
                    })
                except:
                    continue
        
        return patterns_found
    
    def find_suspicious_patterns(self, data):
        """البحث عن أنماط مشبوهة"""
        suspicious = []
        
        # كلمات مرور محتملة
        password_patterns = [
            r'password\s*[:=]\s*[^\s]+',
            r'pass\s*[:=]\s*[^\s]+',
            r'pwd\s*[:=]\s*[^\s]+',
            r'secret\s*[:=]\s*[^\s]+'
        ]
        
        for pattern in password_patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            if matches:
                suspicious.extend([{'type': 'password', 'data': match} for match in matches])
        
        # عناوين IP خاصة
        private_ips = re.findall(r'(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d+\.\d+', data)
        if private_ips:
            suspicious.extend([{'type': 'private_ip', 'data': ip} for ip in private_ips])
        
        # أوامر نظام محتملة
        system_commands = re.findall(r'(?:cmd|bash|sh|powershell|exec)\s+[^\s]+', data, re.IGNORECASE)
        if system_commands:
            suspicious.extend([{'type': 'system_command', 'data': cmd} for cmd in system_commands])
        
        return suspicious
    
    def extract_important_data(self, data):
        """استخراج البيانات المهمة"""
        extracted = []
        
        # عناوين البريد الإلكتروني
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', data)
        if emails:
            extracted.extend([{'type': 'email', 'data': email} for email in emails])
        
        # أرقام الهواتف
        phones = re.findall(r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}', data)
        if phones:
            extracted.extend([{'type': 'phone', 'data': phone} for phone in phones])
        
        # الروابط
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', data)
        if urls:
            extracted.extend([{'type': 'url', 'data': url} for url in urls])
        
        # عناوين IP
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data)
        if ips:
            extracted.extend([{'type': 'ip', 'data': ip} for ip in ips])
        
        return extracted
    
    def extract_forms(self, html_data):
        """استخراج النماذج من HTML"""
        forms = []
        
        # البحث عن نماذج HTML
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html_data, re.DOTALL | re.IGNORECASE)
        
        for form_content in form_matches:
            form_data = {
                'inputs': [],
                'action': None,
                'method': None
            }
            
            # استخراج الحقول
            input_pattern = r'<input[^>]*>'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            for input_tag in inputs:
                name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                type_match = re.search(r'type\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                
                form_data['inputs'].append({
                    'name': name_match.group(1) if name_match else None,
                    'type': type_match.group(1) if type_match else None,
                    'value': value_match.group(1) if value_match else None
                })
            
            forms.append(form_data)
        
        return forms
    
    def extract_credentials(self, data):
        """استخراج بيانات الاعتماد"""
        credentials = []
        
        # أنماط بيانات الاعتماد الشائعة
        patterns = [
            r'username\s*[:=]\s*([^\s]+)',
            r'user\s*[:=]\s*([^\s]+)',
            r'login\s*[:=]\s*([^\s]+)',
            r'password\s*[:=]\s*([^\s]+)',
            r'pass\s*[:=]\s*([^\s]+)',
            r'pwd\s*[:=]\s*([^\s]+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            if matches:
                credentials.extend(matches)
        
        return credentials
    
    def extract_commands(self, data):
        """استخراج الأوامر"""
        commands = []
        
        # أنماط الأوامر الشائعة
        command_patterns = [
            r'(?:^|\n)\s*([a-zA-Z]+(?:\s+[^\n]*)?)',
            r'(?:cmd|bash|sh)\s+(.+)',
            r'(?:sudo|su)\s+(.+)'
        ]
        
        for pattern in command_patterns:
            matches = re.findall(pattern, data, re.MULTILINE)
            if matches:
                commands.extend(matches)
        
        return commands
    
    def detect_tls_version(self, data):
        """كشف إصدار TLS"""
        # هذا مبسط - في الواقع يحتاج تحليل أعمق للحزم
        if b'\x03\x03' in data:
            return 'TLS 1.2'
        elif b'\x03\x04' in data:
            return 'TLS 1.3'
        elif b'\x03\x01' in data:
            return 'TLS 1.0'
        elif b'\x03\x02' in data:
            return 'TLS 1.1'
        else:
            return 'Unknown'


class NetworkStatistics:
    """إحصائيات الشبكة"""
    
    def __init__(self):
        self.reset_stats()
    
    def reset_stats(self):
        """إعادة تعيين الإحصائيات"""
        self.total_packets = 0
        self.protocols = defaultdict(int)
        self.src_ips = defaultdict(int)
        self.dst_ips = defaultdict(int)
        self.ports = defaultdict(int)
        self.packet_sizes = []
        self.suspicious_count = 0
        self.encrypted_count = 0
    
    def update_stats(self, packet_analysis):
        """تحديث الإحصائيات"""
        self.total_packets += 1
        
        basic_info = packet_analysis.get('basic_info', {})
        
        # البروتوكولات
        if 'layers' in basic_info:
            for layer in basic_info['layers']:
                self.protocols[layer] += 1
        
        # عناوين IP
        if 'src_ip' in basic_info:
            self.src_ips[basic_info['src_ip']] += 1
        if 'dst_ip' in basic_info:
            self.dst_ips[basic_info['dst_ip']] += 1
        
        # المنافذ
        if 'src_port' in basic_info:
            self.ports[basic_info['src_port']] += 1
        if 'dst_port' in basic_info:
            self.ports[basic_info['dst_port']] += 1
        
        # أحجام الحزم
        if 'size' in basic_info:
            self.packet_sizes.append(basic_info['size'])
        
        # الأنماط المشبوهة
        if packet_analysis.get('suspicious_patterns'):
            self.suspicious_count += 1
        
        # البيانات المشفرة
        if packet_analysis.get('crypto_analysis'):
            self.encrypted_count += 1
    
    def get_summary(self):
        """الحصول على ملخص الإحصائيات"""
        summary = {
            'total_packets': self.total_packets,
            'top_protocols': dict(sorted(self.protocols.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_src_ips': dict(sorted(self.src_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_dst_ips': dict(sorted(self.dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_ports': dict(sorted(self.ports.items(), key=lambda x: x[1], reverse=True)[:10]),
            'suspicious_packets': self.suspicious_count,
            'encrypted_packets': self.encrypted_count,
            'avg_packet_size': sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
        }
        
        return summary


def test_packet_analyzer():
    """اختبار محلل الحزم"""
    print("🔍 اختبار محلل الحزم المتقدم")
    print("=" * 40)
    
    analyzer = PacketAnalyzer()
    
    # بيانات اختبار HTTP
    http_data = """GET /login.php HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Cookie: session=abc123; user=admin
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret123"""
    
    # تحليل أنماط التشفير
    crypto_analysis = analyzer.analyze_crypto_patterns(http_data)
    print("تحليل التشفير:")
    for pattern, matches in crypto_analysis.items():
        print(f"  {pattern}: {matches}")
    
    # البحث عن أنماط مشبوهة
    suspicious = analyzer.find_suspicious_patterns(http_data)
    print(f"\nالأنماط المشبوهة: {len(suspicious)}")
    for item in suspicious:
        print(f"  {item['type']}: {item['data']}")
    
    # استخراج البيانات المهمة
    extracted = analyzer.extract_important_data(http_data)
    print(f"\nالبيانات المستخرجة: {len(extracted)}")
    for item in extracted:
        print(f"  {item['type']}: {item['data']}")


if __name__ == "__main__":
    test_packet_analyzer()