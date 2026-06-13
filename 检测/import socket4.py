import socket
import re
import json
import csv
import numpy as np
from datetime import datetime
from scapy.all import rdpcap, DNS
import joblib
import pandas as pd

MALICIOUS_DOMAINS = {
    "malware-test.com",
    "phishing-example.org",
    "botnet-command.cc",
    "evil-domain.ru",
    "ad-tracker.net",
    "fake-bank.com"
}
# 频率异常检测配置
FREQUENCY_THRESHOLD = 10  # 短时间高频次阈值（次/分钟）
BURST_THRESHOLD = 3        # 突发访问阈值（次/秒）
IDLE_BURST_THRESHOLD = 2   # 空闲时突发阈值（次/分钟，用户未使用电脑时）
# 高危域名黑名单
HIGH_RISK_DOMAINS = {
    # 已知恶意软件域名
    "zeusbot.com", "conficker.com", "wannacry-ransomware.net", "emotet-malware.com",
    "cobaltstrike.cc", "metasploit.cn", "meterpreter.net",
    # DNS隧道工具常见域名
    "dns-tunnel.com", "iodine-tunnel.org", "dnscat2.net", "tunnelshell.io",
    # 钓鱼仿冒域名
    "fake-microsoft-login.com", "apple-id-verify.net", "paypal-secure.cc",
    # 挖矿木马域名
    "cryptominer-pool.org", "coinhive.com", "javascript-miner.net",
    # 数据外泄相关
    "dataleak-suspicious.net", "exfiltration-domain.com", "c2-panel.org"
}
# 冷门域名检测阈值
COLD_DOMAIN_ACCESS_COUNT = 3   # 访问次数低于此值视为冷门域名
COLD_DOMAIN_TOTAL_THRESHOLD = 0.3  # 冷门域名占总访问比例超过此值视为异常

# 内网IP范围
INTERNAL_IP_RANGES = [
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255'),
]
# 已知恶意IP列表
MALICIOUS_IPS = {
    '192.168.1.100', '10.0.0.100', '172.16.0.50',
    '45.33.32.156', '91.189.92.10', '185.199.108.153'
}

# 资源密集型记录类型配置
RESOURCE_HEAVY_TYPES = {'TXT', 'MX', 'SRV', 'ANY'}
TYPE_FREQUENCY_THRESHOLD=20 # 每分钟查询次数上限

try:
    model_data = joblib.load('dns_ml_model.pkl')
    # 模型保存时是元组 (model, scaler)
    if isinstance(model_data, tuple):
        ML_MODEL = model_data[0]
    else:
        ML_MODEL = model_data
    print("机器学习模型加载成功")
except FileNotFoundError:
    print("机器学习模型文件不存在。")
    ML_MODEL = None
# 频率异常检测函数
def detect_frequency_anomaly(dns_data, is_user_active=True):
    """
    检测DNS查询频率异常
    param dns_data: DNS记录列表，每条记录包含 timestamp 字段
    param is_user_active: 用户是否正在使用电脑
    return 异常检测结果
    """
    result = {
        'has_anomaly': False,
        'anomaly_type': None,
        'details': {},
        'suspicious_domains': []
    }
    if not dns_data or len(dns_data) < 2:
        return result
    # 提取时间戳和域名列表
    timestamps = []
    domains = []
    for item in dns_data:
        if isinstance(item, dict) and 'timestamp' in item:
            timestamps.append(item['timestamp'])
            if 'domain' in item:
                domains.append(item['domain'])
    
    if len(timestamps) < 2:
        return result
    timestamps.sort()
    duration = timestamps[-1] - timestamps[0]
    if duration <= 0:
        return result
    #计算查询频率（次/分钟）
    frequency = len(timestamps) / (duration / 60)
    #1短时间高频次检测
    if frequency > FREQUENCY_THRESHOLD:
        result['has_anomaly'] = True
        result['anomaly_type'] = '高频访问'
        result['details'] = {
            'frequency': round(frequency, 2),
            'threshold': FREQUENCY_THRESHOLD,
            'query_count': len(timestamps),
            'duration_seconds': round(duration, 2)
        }
    #2突发访问检测（计算每秒查询数）
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    if intervals:
        min_interval = min(intervals)
        if min_interval > 0:
            queries_per_second = 1 / min_interval
            if queries_per_second > BURST_THRESHOLD:
                result['has_anomaly'] = True
                result['anomaly_type'] = '突发访问'
                result['details'] = {
                    'queries_per_second': round(queries_per_second, 2),
                    'threshold': BURST_THRESHOLD,
                    'min_interval_ms': round(min_interval * 1000, 2)
                }
    #3空闲时段异常检测（用户未使用电脑时却有高频访问）
    if not is_user_active and frequency > IDLE_BURST_THRESHOLD:
        result['has_anomaly']=True
        result['anomaly_type'] = '空闲异常'
        result['details'] = {
            'frequency': round(frequency, 2),
            'threshold': IDLE_BURST_THRESHOLD,
            'warning': '用户未使用电脑时检测到高频DNS访问，可能存在恶意攻击'
        }
    
    #收集高频访问的域名
    if result['has_anomaly']:
        domain_counts = {}
        for domain in domains:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        # 返回访问次数最多的域名
        sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
        result['suspicious_domains'] = sorted_domains[:5]
    return result

# 访问对象异常检测函数
def detect_access_pattern_anomaly(dns_data):
    """
    检测访问对象异常：冷门域名、高危域名、异常TLD等
    param dns_data: DNS记录列表，每条记录包含 domain 字段
    return 异常检测结果
    """
    result = {
        'has_anomaly': False,
        'anomaly_types': [],
        'high_risk_domains': [],
        'cold_domains': [],
        'suspicious_tld_domains': [],
        'details': {}
    }
    
    if not dns_data:
        return result
    
    #提取域名列表
    domains = []
    for item in dns_data:
        if isinstance(item, dict) and 'domain' in item:
            domains.append(item['domain'])
        elif isinstance(item, str):
            domains.append(item)
    
    if not domains:
        return result
    
    # 统计各域名访问次数
    domain_counts = {}
    for domain in domains:
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
    total_access = len(domains)
    unique_domains = len(domain_counts)
    #1高危域名检测
    high_risk_found = []
    for domain in domain_counts.keys():
        if domain in HIGH_RISK_DOMAINS:
            high_risk_found.append({
                'domain': domain,
                'access_count': domain_counts[domain],
                'reason': '命中高危域名黑名单'
            })
    if high_risk_found:
        result['has_anomaly'] = True
        result['anomaly_types'].append('高危域名')
        result['high_risk_domains'] = high_risk_found
        result['details']['high_risk_count'] = len(high_risk_found)
    #2冷门域名检测（访问量少的域名占比过高）
    cold_domains = []
    for domain, count in domain_counts.items():
        if count <= COLD_DOMAIN_ACCESS_COUNT:
            cold_domains.append({
                'domain': domain,
                'access_count': count,
                'reason': f'冷门域名（仅访问{count}次）'
            })
    cold_domain_ratio = len(cold_domains) / unique_domains if unique_domains > 0 else 0
    if cold_domain_ratio > COLD_DOMAIN_TOTAL_THRESHOLD:
        result['has_anomaly'] = True
        result['anomaly_types'].append('冷门域名占比过高')
        result['cold_domains'] = cold_domains[:10]  # 最多返回10个
        result['details']['cold_domain_ratio'] = round(cold_domain_ratio, 2)
        result['details']['cold_domain_count'] = len(cold_domains)
        result['details']['total_unique_domains'] = unique_domains
    
    return result

# 响应异常检测函数
def detect_response_anomaly(dns_data):
    """
    检测DNS响应异常：域名不存在、返回内网IP、恶意IP等
    param dns_data: DNS记录列表，每条记录包含 domain 和 response 字段
    return 异常检测结果
    """
    result = {
        'has_anomaly': False,
        'anomaly_types': [],
        'non_existent_domains': [],
        'internal_ip_responses': [],
        'malicious_ip_responses': [],
        'details': {}
    }
    
    if not dns_data:
        return result
    
    # 辅助函数：判断IP是否为内网IP
    def is_internal_ip(ip):
        try:
            ip_parts = list(map(int, ip.split('.')))
            for start, end in INTERNAL_IP_RANGES:
                start_parts = list(map(int, start.split('.')))
                end_parts = list(map(int, end.split('.')))
                if all(start_parts[i] <= ip_parts[i] <= end_parts[i] for i in range(4)):
                    return True
            return False
        except:
            return False
    
    #辅助函数：验证域名是否存在
    def domain_exists(domain):
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False
    
    non_existent_count = 0
    internal_ip_count = 0
    malicious_ip_count = 0
    
    for item in dns_data:
        if isinstance(item, dict):
            domain = item.get('domain', '')
            response = item.get('response', '')
            
            #1检测域名不存在的响应
            if domain and response and 'NXDOMAIN' in response.upper():
                non_existent_count += 1
                if domain not in [d['domain'] for d in result['non_existent_domains']]:
                    result['non_existent_domains'].append({
                        'domain': domain,
                        'response': response,
                        'reason': '域名不存在(NXDOMAIN)'
                    })
            
            #2检测返回内网IP
            if response:
                # 提取IP地址
                import re
                ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
                ips = ip_pattern.findall(response)
                for ip in ips:
                    if is_internal_ip(ip):
                        internal_ip_count += 1
                        if domain not in [d['domain'] for d in result['internal_ip_responses']]:
                            result['internal_ip_responses'].append({
                                'domain': domain,
                                'ip': ip,
                                'reason': 'DNS响应返回内网IP'
                            })
                
                #3检测返回恶意IP
                for ip in ips:
                    if ip in MALICIOUS_IPS:
                        malicious_ip_count += 1
                        if domain not in [d['domain'] for d in result['malicious_ip_responses']]:
                            result['malicious_ip_responses'].append({
                                'domain': domain,
                                'ip': ip,
                                'reason': 'DNS响应返回已知恶意IP'
                            })
    
    # 设置异常结果
    if non_existent_count > 0:
        result['has_anomaly'] = True
        result['anomaly_types'].append('域名不存在')
        result['details']['non_existent_count'] = non_existent_count
    
    if internal_ip_count > 0:
        result['has_anomaly'] = True
        result['anomaly_types'].append('返回内网IP')
        result['details']['internal_ip_count'] = internal_ip_count
    
    if malicious_ip_count > 0:
        result['has_anomaly'] = True
        result['anomaly_types'].append('返回恶意IP')
        result['details']['malicious_ip_count'] = malicious_ip_count
    
    return result

# DNS记录类型到名称的映射
DNS_TYPE_MAP = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
    16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'
}

def get_dns_type_name(qtype):
    """将DNS类型编号转换为名称"""
    return DNS_TYPE_MAP.get(qtype, f'UNKNOWN({qtype})')

# 记录类型异常检测函数
def detect_record_type_anomaly(dns_data):
    """
    检测DNS记录类型异常：频繁查询TXT/MX等资源密集型记录
    param dns_data: DNS记录列表，每条记录包含 type 字段
    return 异常检测结果
    """
    result = {
        'has_anomaly': False,
        'anomaly_types': [],
        'heavy_type_records': [],
        'details': {}
    }
    
    if not dns_data:
        return result
    
    # 统计各类型查询次数
    type_counts = {}
    heavy_type_count = 0
    total_queries = 0
    timestamps = []
    
    for item in dns_data:
        if isinstance(item, dict):
            qtype = item.get('type', 'A')
            timestamp = item.get('timestamp')
            if timestamp:
                timestamps.append(timestamp)
            type_counts[qtype] = type_counts.get(qtype, 0) + 1
            total_queries += 1
            # 检查是否为资源密集型类型
            if isinstance(qtype, int):
                qtype_name = get_dns_type_name(qtype)
            else:
                qtype_name = str(qtype).upper()
            if qtype_name in RESOURCE_HEAVY_TYPES:
                heavy_type_count += 1
                if qtype not in [r['type'] for r in result['heavy_type_records']]:
                    result['heavy_type_records'].append({
                        'type': qtype,
                        'type_name': qtype_name,
                        'domain': item.get('domain', ''),
                        'count': 0
                    })
    
    # 更新各资源密集型类型的计数
    for rec in result['heavy_type_records']:
        rec['count'] = type_counts.get(rec['type'], 0)
    
    # 计算频率（次/分钟）
    frequency = 0
    if timestamps and len(timestamps) >= 5:
        timestamps.sort()
        duration = timestamps[-1] - timestamps[0]
        if duration > 0:
            frequency = heavy_type_count / (duration / 60)
    
    # 检测频繁查询资源密集型记录
    if frequency > TYPE_FREQUENCY_THRESHOLD:
        result['has_anomaly'] = True
        result['anomaly_types'].append('频繁查询资源密集型记录')
        result['details'] = {
            'heavy_type_frequency': round(frequency, 2),
            'threshold': TYPE_FREQUENCY_THRESHOLD,
            'heavy_type_count': heavy_type_count,
            'total_queries': total_queries,
            'heavy_type_ratio': round(heavy_type_count / total_queries * 100, 2) if total_queries > 0 else 0
        }
    
    # 检测单一类型过度使用
    for qtype, count in type_counts.items():
        if isinstance(qtype, int):
            qtype_name = get_dns_type_name(qtype)
        else:
            qtype_name = str(qtype).upper()
        if qtype_name in RESOURCE_HEAVY_TYPES:
            ratio = count / total_queries if total_queries > 0 else 0
            if ratio > 0.3:  # 超过30%的查询是资源密集型类型
                if '单一类型过度使用' not in result['anomaly_types']:
                    result['has_anomaly'] = True
                    result['anomaly_types'].append('单一类型过度使用')
                result['details'][f'{qtype_name}_ratio'] = round(ratio * 100, 2)
    
    return result

def is_base64_encoded(domain):
    clean_domain = domain.replace('.', '')
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
    return bool(base64_pattern.match(clean_domain))

def is_hex_encoded(domain):
    clean_domain = domain.replace('.', '')
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    return bool(hex_pattern.match(clean_domain)) and len(clean_domain) >= 8

def calculate_avg_subdomain_length(domain):
    parts = domain.split('.')
    if len(parts) <= 1:
        return 0
    lengths = [len(part) for part in parts[:-1]]
    return sum(lengths) / len(lengths) if lengths else 0

def calculate_max_subdomain_length(domain):
    parts = domain.split('.')
    if len(parts) <= 1:
        return 0
    lengths = [len(part) for part in parts[:-1]]
    return max(lengths) if lengths else 0

def calculate_entropy(domain):
    import math
    clean_domain = domain.replace('.', '')
    if not clean_domain:
        return 0
    freq = {}
    for char in clean_domain:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0
    for count in freq.values():
        probability = count / len(clean_domain)
        entropy -= probability * math.log2(probability)
    return entropy

def has_repeated_patterns(domain):
    parts = domain.split('.')
    if len(parts) < 3:
        return False
    seen = set()
    for part in parts[:-1]:
        if part in seen:
            return True
        seen.add(part)
    for i in range(len(domain) - 3):
        pattern = domain[i:i+3]
        if domain.count(pattern) > 1:
            return True
    return False

def has_consecutive_chars(domain):
    for i in range(len(domain) - 2):
        if domain[i] == domain[i+1] == domain[i+2]:
            return True
    return False

def extract_features(domain):
    features = {}
    features['length'] = len(domain)
    features['digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
    features['special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', domain))
    features['subdomains'] = domain.count('.')
    features['has_long_random'] = 1 if re.search(r'[a-z0-9]{15,}', domain) else 0
    features['has_idn'] = 1 if 'xn--' in domain else 0
    features['is_base64'] = 1 if is_base64_encoded(domain) else 0
    features['is_hex_encoded'] = 1 if is_hex_encoded(domain) else 0
    features['avg_subdomain_length'] = calculate_avg_subdomain_length(domain)
    features['max_subdomain_length'] = calculate_max_subdomain_length(domain)
    features['domain_entropy'] = calculate_entropy(domain)
    features['has_repeated_patterns'] = 1 if has_repeated_patterns(domain) else 0
    features['has_consecutive_chars'] = 1 if has_consecutive_chars(domain) else 0
    return features

def predict_with_ml(domain):
    if ML_MODEL is None:
        return None
    feat = extract_features(domain)
    feat_df = pd.DataFrame([feat])
    numeric_features = ['length', 'digit_ratio', 'special_chars', 'subdomains', 'has_long_random', 'has_idn',
                       'is_base64', 'is_hex_encoded', 'avg_subdomain_length', 'max_subdomain_length',
                       'domain_entropy', 'has_repeated_patterns', 'has_consecutive_chars']
    feat_df = feat_df[numeric_features]
    prediction = ML_MODEL.predict(feat_df)[0]
    probability = ML_MODEL.predict_proba(feat_df)[0][1]
    return {
        'is_malicious': bool(prediction),
        'confidence': probability
    }

SUSPICIOUS_PATTERNS = [
    re.compile(r'\d{5,}'),
    re.compile(r'[a-z0-9]{20,}'),
    re.compile(r'xn--'),
    re.compile(r'\.top$'),
    re.compile(r'\.work$'),
    re.compile(r'\.club$')
]
def check_dns_record(domain: str) -> dict:
    result = {
        "domain": domain,
        "is_malicious": False,
        "is_suspicious": False,
        "reason": "正常",
        "resolve_ip": None,
        "ml_prediction": None,
        "ml_confidence": 0.0
    }
    if domain in MALICIOUS_DOMAINS:
        result["is_malicious"] = True
        result["reason"] = "命中恶意域名黑名单"
        return result
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(domain):
            result["is_suspicious"] = True
            result["reason"] = "域名特征异常"
            break
    try:
        ip = socket.gethostbyname(domain)
        result["resolve_ip"] = ip
    except Exception:
        result["resolve_ip"] = "解析失败"
        if not result["is_suspicious"]:
            result["is_suspicious"] = True
            result["reason"] = "域名无法解析"
    ml_result = predict_with_ml(domain)
    if ml_result:
        result["ml_prediction"] = ml_result["is_malicious"]
        result["ml_confidence"] = ml_result["confidence"]
        if ml_result["is_malicious"] and ml_result["confidence"] > 0.7:
            result["is_malicious"] = True
            result["reason"] = "模型检测为恶意"
    return result

def load_dns_log(file_path: str = "dns_log.txt") -> list:
    dns_records = []
    try:
        if file_path.endswith(".json"):
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    if data and isinstance(data[0], str):
                        # 纯域名列表，生成时间戳
                        import time
                        for i, domain in enumerate(data):
                            dns_records.append({
                                'domain': domain,
                                'timestamp': time.time() - (len(data) - i)
                            })
                    elif data and isinstance(data[0], dict):
                        for item in data:
                            record = {}
                            for key in ["domain", "name", "host", "url"]:
                                if key in item and isinstance(item[key], str):
                                    record['domain'] = item[key]
                                    break
                            # 尝试提取时间戳
                            for ts_key in ["timestamp", "time", "datetime", "@timestamp"]:
                                if ts_key in item:
                                    record['timestamp'] = item[ts_key]
                                    break
                            if 'domain' in record:
                                dns_records.append(record)
        elif file_path.endswith(".csv"):
            with open(file_path, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    record = {}
                    for key in ["domain", "name", "host", "url"]:
                        if key in row and row[key]:
                            record['domain'] = row[key]
                            break
                    # 尝试提取时间戳
                    for ts_key in ["timestamp", "time", "datetime"]:
                        if ts_key in row:
                            try:
                                record['timestamp'] = float(row[ts_key])
                            except:
                                pass
                    if 'domain' in record:
                        if 'timestamp' not in record:
                            import time
                            record['timestamp'] = time.time()
                        dns_records.append(record)
        elif file_path.endswith(".pcapng") or file_path.endswith(".pcap"):
            try:
                packets = rdpcap(file_path)
                for packet in packets:
                    if packet.haslayer(DNS) and packet[DNS].qr == 0:
                        for i in range(packet[DNS].qdcount):
                            qname = packet[DNS].qd[i].qname.decode('utf-8', errors='ignore').rstrip('.')
                            qtype = packet[DNS].qd[i].qtype if hasattr(packet[DNS].qd[i], 'qtype') else 1
                            if qname:
                                dns_records.append({
                                    'domain': qname,
                                    'timestamp': float(packet.time),
                                    'type': qtype
                                })
            except Exception as e:
                print(f"解析PCAP文件时出错：{e}")
        else:
            import time
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        dns_records.append({
                            'domain': line,
                            'timestamp': time.time() - (len(lines) - i)
                        })
    except FileNotFoundError:
        print(f"未找到 {file_path}")
        return []
    except Exception as e:
        print(f"读取文件 {file_path} 时出错：{e}")
        return []
    return dns_records

if __name__ == "__main__":
    print(f"检测开始时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    import sys
    file_path = "dns_log.txt"
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        user_input = input(f"请输入DNS数据文件路径或pcapng文件路径：").strip()
        if not user_input:
            print("未输入文件路径，程序退出")
            sys.exit(0)
        user_input = user_input.strip('"').strip("'")
        file_path = user_input
    dns_records = load_dns_log(file_path)
    if not dns_records:
        print("未加载到任何DNS记录，程序退出")
        sys.exit(0)
    print(f"\n从 {file_path} 共加载 {len(dns_records)} 条DNS记录\n")
    
    # 提取域名列表（兼容原有检测逻辑）
    dns_domains = [record.get('domain', '') for record in dns_records]
    
    #1频率异常检测
    print("正在进行频率异常检测...")
    freq_result = detect_frequency_anomaly(dns_records)
    if freq_result['has_anomaly']:
        print(f"\n频率异常检测告警：")
        print(f"   异常类型：{freq_result['anomaly_type']}")
        print(f"   详情：{freq_result['details']}")
        if freq_result['suspicious_domains']:
            print(f"   高频访问域名：")
            for domain, count in freq_result['suspicious_domains']:
                print(f"     - {domain}: {count}次")
    else:
        print("频率异常检测通过")
    #2访问对象异常检测
    access_result = detect_access_pattern_anomaly(dns_records)
    if access_result['has_anomaly']:
        print(f"\n访问对象异常告警：")
        for anomaly_type in access_result['anomaly_types']:
            print(f"   - {anomaly_type}")
    
        # 高危域名详情
        if access_result['high_risk_domains']:
            print(f"\n高危域名（{len(access_result['high_risk_domains'])}个）：")
            for item in access_result['high_risk_domains'][:5]:
                print(f"     - {item['domain']} (访问{item['access_count']}次)")
        
        # 冷门域名详情
        if access_result['cold_domains']:
            ratio = access_result['details'].get('cold_domain_ratio', 0)
            print(f"\n冷门域名占比过高：{ratio*100:.1f}%")
            print(f"   (共{access_result['details'].get('cold_domain_count', 0)}个冷门域名，"
                  f"总唯一域名{access_result['details'].get('total_unique_domains', 0)}个)")
            for item in access_result['cold_domains'][:5]:
                print(f"     - {item['domain']} (仅{item['access_count']}次)")
        # 异常TLD域名
        if access_result['suspicious_tld_domains']:
            print(f"\n异常顶级域名（{access_result['details'].get('suspicious_tld_count', 0)}个）：")
            for item in access_result['suspicious_tld_domains'][:5]:
                print(f" - {item['domain']} (TLD: {item['tld']})")
    else:
        print("访问对象异常检测通过")
    
    #3响应异常检测
    print("\n正在进行响应异常检测...")
    response_result = detect_response_anomaly(dns_records)
    if response_result['has_anomaly']:
        print(f"\n响应异常检测告警：")
        for anomaly_type in response_result['anomaly_types']:
            print(f"   - {anomaly_type}")
        
        # 域名不存在详情
        if response_result['non_existent_domains']:
            print(f"\n域名不存在（{len(response_result['non_existent_domains'])}个）：")
            for item in response_result['non_existent_domains'][:5]:
                print(f"     - {item['domain']}")
        
        # 返回内网IP详情
        if response_result['internal_ip_responses']:
            print(f"\n返回内网IP（{len(response_result['internal_ip_responses'])}个）：")
            for item in response_result['internal_ip_responses'][:5]:
                print(f"     - {item['domain']} -> {item['ip']}")
        
        # 返回恶意IP详情
        if response_result['malicious_ip_responses']:
            print(f"\n返回恶意IP（{len(response_result['malicious_ip_responses'])}个）：")
            for item in response_result['malicious_ip_responses'][:5]:
                print(f"     - {item['domain']} -> {item['ip']}")
    else:
        print("响应异常检测通过")
    
    #4记录类型异常检测（检测频繁查询TXT/MX等资源密集型记录）
    print("\n正在进行记录类型异常检测...")
    type_result = detect_record_type_anomaly(dns_records)
    if type_result['has_anomaly']:
        print(f"\n记录类型异常检测告警：")
        for anomaly_type in type_result['anomaly_types']:
            print(f"   - {anomaly_type}")
        
        # 详细信息
        details = type_result['details']
        if 'heavy_type_frequency' in details:
            print(f"\n资源密集型记录查询频率：{details['heavy_type_frequency']}次/分钟")
            print(f"阈值：{details['threshold']}次/分钟")
            print(f"资源密集型记录数：{details['heavy_type_count']}条（占总查询的{details['heavy_type_ratio']}%）")
        
        # 资源密集型类型详情
        if type_result['heavy_type_records']:
            print(f"\n检测到的资源密集型记录类型：")
            for rec in type_result['heavy_type_records']:
                print(f"   - {rec['type_name']} (类型码: {rec['type']}): {rec['count']}次")
                if rec['domain']:
                    print(f"     示例域名: {rec['domain']}")
    else:
        print("记录类型异常检测通过")
    
    #5域名恶意检测 
    malicious_list = []
    suspicious_list = []
    normal_list = []
    for record in dns_records:
        domain = record.get('domain', '')
        if not domain:
            continue
        res = check_dns_record(domain)
        print(f"【检测】{domain:30} | {res['reason']}")
        if res["is_malicious"]:
            malicious_list.append(res)
        elif res["is_suspicious"]:
            suspicious_list.append(res)
        else:
            normal_list.append(res)
    print("\n" + "=" * 60)
    print("检测报告")
    print(f"正常域名：{len(normal_list)} 个")
    print(f"可疑域名：{len(suspicious_list)} 个")
    print(f"恶意域名：{len(malicious_list)} 个")
    if malicious_list:
        print("\n发现恶意域名：")
        for item in malicious_list:
            print(f"  - {item['domain']} | {item['reason']}")
    if suspicious_list:
        print("\n发现可疑域名：")
        for item in suspicious_list:
            print(f"  - {item['domain']} | {item['reason']}")
    print(f"\n检测完成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
