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
BURST_THRESHOLD = 5        # 突发访问阈值（次/秒）
IDLE_BURST_THRESHOLD = 3   # 空闲时突发阈值（次/分钟，在检测到用户未使用电脑时）

try:
    ML_MODEL = joblib.load('dns_malware_model.pkl')
    print("机器学习模型加载成功")
except FileNotFoundError:
    print("机器学习模型文件不存在。")
    ML_MODEL = None

# 频率异常检测函数
def detect_frequency_anomaly(dns_data, is_user_active=True):
    """
    检测DNS查询频率异常
    :param dns_data: DNS记录列表，每条记录包含 timestamp 字段
    :param is_user_active: 用户是否正在使用电脑
    :return: 异常检测结果
    """
    result = {
        'has_anomaly': False,
        'anomaly_type': None,
        'details': {},
        'suspicious_domains': []
    }
    
    if not dns_data or len(dns_data) < 2:
        return result
    
    # 提取时间戳
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
    
    # 计算查询频率（次/分钟）
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
        result['has_anomaly'] = True
        result['anomaly_type'] = '空闲异常'
        result['details'] = {
            'frequency': round(frequency, 2),
            'threshold': IDLE_BURST_THRESHOLD,
            'warning': '用户未使用电脑时检测到高频DNS访问，可能存在后台恶意软件'
        }
    
    # 收集高频访问的域名
    if result['has_anomaly']:
        domain_counts = {}
        for domain in domains:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        # 返回访问次数最多的域名
        sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
        result['suspicious_domains'] = sorted_domains[:5]
    
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
            result["reason"] = f"命中可疑特征：{pattern.pattern}"
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
            result["reason"] = f"机器学习模型预测为恶意（置信度：{ml_result['confidence']:.2f}）"
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
                            if qname:
                                dns_records.append({
                                    'domain': qname,
                                    'timestamp': float(packet.time)
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
        print(f"\n 频率异常检测告警：")
        print(f"   异常类型：{freq_result['anomaly_type']}")
        print(f"   详情：{freq_result['details']}")
        if freq_result['suspicious_domains']:
            print(f"   高频访问域名：")
            for domain, count in freq_result['suspicious_domains']:
                print(f"     - {domain}: {count}次")
    else:
        print("频率异常检测通过")
    
    #2域名恶意检测
    print("\n正在进行域名恶意检测...")
    malicious_list = []
    suspicious_list = []
    normal_list = []
    for record in dns_records:
        domain = record.get('domain', '')
        if not domain:
            continue
        res = check_dns_record(domain)
        ml_info = f" | ML预测: {'恶意' if res.get('ml_prediction') else '正常'} (置信度: {res.get('ml_confidence', 0):.2f})" if res.get('ml_prediction') is not None else ""
        print(f"【检测】{domain:30} | {res['reason']}{ml_info}")
        if res["is_malicious"]:
            malicious_list.append(res)
        elif res["is_suspicious"]:
            suspicious_list.append(res)
        else:
            normal_list.append(res)
    #尝试提取时间戳
    print("\n" + "=" * 60)
    print("检测报告")
    print(f"正常域名：{len(normal_list)} 个")
    print(f"可疑域名：{len(suspicious_list)} 个")
    print(f"恶意域名：{len(malicious_list)} 个")
    if malicious_list:
        print("\n发现恶意域名：")
        for item in malicious_list:
            ml_info = f" | ML预测: {'恶意' if item.get('ml_prediction') else '正常'} (置信度: {item.get('ml_confidence', 0):.2f})" if item.get('ml_prediction') is not None else ""
            print(f"  - {item['domain']} | {item['reason']}{ml_info}")
    if suspicious_list:
        print("\n发现可疑域名：")
        for item in suspicious_list:
            ml_info = f" | ML预测: {'恶意' if item.get('ml_prediction') else '正常'} (置信度: {item.get('ml_confidence', 0):.2f})" if item.get('ml_prediction') is not None else ""
            print(f"  - {item['domain']} | {item['reason']}{ml_info}")
    print(f"\n检测完成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
