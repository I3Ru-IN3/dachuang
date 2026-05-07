import socket
import re
import json
import csv
import numpy as np
from datetime import datetime
from scapy.all import rdpcap, DNS
import joblib
import pandas as pd

#恶意DNS域名黑名单（后面证据累积后直接加到这里）
MALICIOUS_DOMAINS = {
    "malware-test.com",
    "phishing-example.org",
    "botnet-command.cc",
    "evil-domain.ru",
    "ad-tracker.net",
    "fake-bank.com"
}

#加载机器学习模型
try:
    ML_MODEL = joblib.load('dns_malware_model.pkl')
    print("机器学习模型加载成功")
except FileNotFoundError:
    print("机器学习模型文件不存在。")
    ML_MODEL = None

#检测Base64编码
def is_base64_encoded(domain):
    # 移除点号后检查是否符合Base64编码特征
    clean_domain = domain.replace('.', '')
    # Base64编码通常只包含A-Z, a-z, 0-9, +, /
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
    return bool(base64_pattern.match(clean_domain))

#检测十六进制编码
def is_hex_encoded(domain):
    # 移除点号后检查是否全为十六进制字符
    clean_domain = domain.replace('.', '')
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    return bool(hex_pattern.match(clean_domain)) and len(clean_domain) >= 8

#计算平均子域名长度
def calculate_avg_subdomain_length(domain):
    parts = domain.split('.')
    if len(parts) <= 1:
        return 0
    lengths = [len(part) for part in parts[:-1]]  # 排除顶级域名
    return sum(lengths) / len(lengths) if lengths else 0

#计算最大子域名长度
def calculate_max_subdomain_length(domain):
    parts = domain.split('.')
    if len(parts) <= 1:
        return 0
    lengths = [len(part) for part in parts[:-1]]  # 排除顶级域名
    return max(lengths) if lengths else 0

#计算域名熵值（衡量随机性）
def calculate_entropy(domain):
    import math
    clean_domain = domain.replace('.', '')
    if not clean_domain:
        return 0
    
    #计算字符频率
    freq = {}
    for char in clean_domain:
        freq[char] = freq.get(char, 0) + 1
    
    #计算熵值
    entropy = 0
    for count in freq.values():
        probability = count / len(clean_domain)
        entropy -= probability * math.log2(probability)
    
    return entropy

#检测重复模式
def has_repeated_patterns(domain):
    # 检测是否有重复的子域名模式
    parts = domain.split('.')
    if len(parts) < 3:
        return False
    
    #检查是否有重复的子域名
    seen = set()
    for part in parts[:-1]:
        if part in seen:
            return True
        seen.add(part)
    
    #检查是否有重复的字符模式
    for i in range(len(domain) - 3):
        pattern = domain[i:i+3]
        if domain.count(pattern) > 1:
            return True
    
    return False

#计算连续字符       
def has_consecutive_chars(domain):
    #检测是否有连续的相同字符
    for i in range(len(domain) - 2):
        if domain[i] == domain[i+1] == domain[i+2]:
            return True
    return False

#特征融合框架 
#特征权重配置
ENCODING_WEIGHTS = {
    'entropy': 0.25,
    'is_base64': 0.15,
    'is_hex': 0.15,
    'avg_subdomain_length': 0.10,
    'max_subdomain_length': 0.10,
    'has_repeated_patterns': 0.10,
    'consecutive_chars': 0.08,
    'digit_ratio': 0.07
}

BEHAVIOR_WEIGHTS = {
    'query_frequency': 0.20,
    'unique_domain_ratio': 0.15,
    'non_ip_query_ratio': 0.20,
    'avg_response_time': 0.15,
    'query_burst_score': 0.15,
    'ttl_anomaly_score': 0.10,
    'packet_size_variance': 0.05
}

COMBINE_WEIGHT = 0.5 

#提取编码特征（静态特征）
def extract_encoding_features(domain):
    features = {}
    features['entropy'] = calculate_entropy(domain)
    features['is_base64'] = 1 if is_base64_encoded(domain) else 0
    features['is_hex'] = 1 if is_hex_encoded(domain) else 0
    features['avg_subdomain_length'] = calculate_avg_subdomain_length(domain)
    features['max_subdomain_length'] = calculate_max_subdomain_length(domain)
    features['has_repeated_patterns'] = 1 if has_repeated_patterns(domain) else 0
    features['consecutive_chars'] = 1 if has_consecutive_chars(domain) else 0
    features['digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
    return features

#提取行为特征（动态特征，需要会话数据）
def extract_behavioral_features(dns_session):
    features = {}
    
    #查询频率（每分钟查询数）
    duration = dns_session.get('duration', 60) or 60
    query_count = dns_session.get('query_count', 1)
    features['query_frequency'] = query_count / (duration / 60)
    
    #唯一域名比例
    total_queries = dns_session.get('query_count', 1)
    unique_count = len(dns_session.get('unique_domains', []))
    features['unique_domain_ratio'] = unique_count / total_queries if total_queries > 0 else 1.0
    
    #非IP类型查询比例
    non_ip_count = dns_session.get('non_ip_count', 0)
    features['non_ip_query_ratio'] = non_ip_count / total_queries if total_queries > 0 else 0.0
    
    #平均响应时间
    response_times = dns_session.get('response_times', [])
    features['avg_response_time'] = np.mean(response_times) if response_times else 0.0
    
    #查询突发分数       
    timestamps = dns_session.get('timestamps', [])
    features['query_burst_score'] = calculate_burst_score(timestamps)
    
    #计算TTL异常分数        
    ttl_values = dns_session.get('ttl_values', [])
    features['ttl_anomaly_score'] = calculate_ttl_anomaly(ttl_values)
    
    #计算报文大小方差
    packet_sizes = dns_session.get('packet_sizes', [])
    features['packet_size_variance'] = np.var(packet_sizes) if len(packet_sizes) > 1 else 0.0
    
    return features

#计算查询突发分数
def calculate_burst_score(timestamps):
    if len(timestamps) < 2:
        return 0.0
    timestamps.sort()
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    avg_interval = np.mean(intervals)
    min_interval = np.min(intervals)
    # 突发分数：间隔越小，分数越高（表示可能存在隧道数据传输）
    return 1.0 - (min_interval / avg_interval) if avg_interval > 0 else 0.0

#计算TTL异常分数
def calculate_ttl_anomaly(ttl_values):
    if len(ttl_values) < 3:
        return 0.0
    mean_ttl = np.mean(ttl_values)
    std_ttl = np.std(ttl_values)
    # 异常分数：TTL标准差越大，分数越高
    return std_ttl / mean_ttl if mean_ttl > 0 else 0.0

#特征融合函数
def fuse_features(encoding_features, behavioral_features):
    #计算编码特征得分
    encoding_score = 0.0
    for key, weight in ENCODING_WEIGHTS.items():
        encoding_score += encoding_features.get(key, 0) * weight
    
    #计算行为特征得分（归一化）
    behavior_score = 0.0
    for key, weight in BEHAVIOR_WEIGHTS.items():
        value = behavioral_features.get(key, 0)
        #归一化处理
        if key == 'avg_response_time':
            value = min(value / 5000, 1.0)  # 超过5秒视为异常
        elif key == 'packet_size_variance':
            value = min(value / 10000, 1.0)  # 方差超过10000视为异常
        behavior_score += value * weight
    
    #融合得分
    combined_score = COMBINE_WEIGHT * encoding_score + (1 - COMBINE_WEIGHT) * behavior_score
    
    return {
        'encoding_score': encoding_score,
        'behavior_score': behavior_score,
        'combined_score': combined_score,
        'encoding_features': encoding_features,
        'behavioral_features': behavioral_features
    }

#基于融合特征的隧道检测
def fused_tunnel_detection(domain, dns_session=None):
    # 如果没有会话数据，仅使用编码特征
    if dns_session is None:
        dns_session = {
            'duration': 60,
            'query_count': 1,
            'unique_domains': [domain],
            'non_ip_count': 0,
            'response_times': [],
            'timestamps': [0],
            'ttl_values': [3600],
            'packet_sizes': [50]
        }
    
    #提取特征
    encoding_features = extract_encoding_features(domain)
    behavioral_features = extract_behavioral_features(dns_session)
    
    #特征融合
    fused_result = fuse_features(encoding_features, behavioral_features)
    
    #决策判定
    combined_score = fused_result['combined_score']
    encoding_score = fused_result['encoding_score']
    behavior_score = fused_result['behavior_score']
    
    if combined_score > 0.7:
        result = '恶意隧道'
        confidence = min(combined_score * 1.2, 1.0)
    elif combined_score > 0.4:
        result = '可疑'
        confidence = combined_score
    else:
        result = '正常'
        confidence = 1.0 - combined_score
    
    return {
        'domain': domain,
        'result': result,
        'confidence': confidence,
        'encoding_score': encoding_score,
        'behavior_score': behavior_score,
        'combined_score': combined_score,
        'features': {**encoding_features, **behavioral_features}
    }

#域名特征提取函数
def extract_features(domain):
    features = {}
    #域名长度
    features['length'] = len(domain)
    # 数字比例
    features['digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
    # 特殊字符数量
    features['special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', domain))
    # 子域名数量
    features['subdomains'] = domain.count('.')
    # 是否包含长随机字符串
    features['has_long_random'] = 1 if re.search(r'[a-z0-9]{15,}', domain) else 0
    # 是否包含国际域名标记
    features['has_idn'] = 1 if 'xn--' in domain else 0
    
    #DNS隐蔽信道特征
    #编码特征检测
    features['is_base64'] = 1 if is_base64_encoded(domain) else 0
    features['is_hex_encoded'] = 1 if is_hex_encoded(domain) else 0
    #域名结构特征
    features['avg_subdomain_length'] = calculate_avg_subdomain_length(domain)
    features['max_subdomain_length'] = calculate_max_subdomain_length(domain)
    #熵值（衡量随机性）
    features['domain_entropy'] = calculate_entropy(domain)
    #特殊模式检测
    features['has_repeated_patterns'] = 1 if has_repeated_patterns(domain) else 0
    features['has_consecutive_chars'] = 1 if has_consecutive_chars(domain) else 0
    
    return features

#使用机器学习模型预测
def predict_with_ml(domain):
    if ML_MODEL is None:
        return None
    
    #提取特征
    feat = extract_features(domain)
    feat_df = pd.DataFrame([feat])
    numeric_features = ['length', 'digit_ratio', 'special_chars', 'subdomains', 'has_long_random', 'has_idn',
                       'is_base64', 'is_hex_encoded', 'avg_subdomain_length', 'max_subdomain_length',
                       'domain_entropy', 'has_repeated_patterns', 'has_consecutive_chars']
    feat_df = feat_df[numeric_features]
    
    #预测
    prediction = ML_MODEL.predict(feat_df)[0]
    probability = ML_MODEL.predict_proba(feat_df)[0][1]
    
    return {
        'is_malicious': bool(prediction),
        'confidence': probability
    }

#可疑特征
SUSPICIOUS_PATTERNS = [
    re.compile(r'\d{5,}'),          # 有大量数字
    re.compile(r'[a-z0-9]{20,}'),   # 有超长随机字符串
    re.compile(r'xn--'),            # 恶意域名常用表达
    re.compile(r'\.top$'),          # 恶意域名常用后缀
    re.compile(r'\.work$'),
    re.compile(r'\.club$')
]

#检测部分
def check_dns_record(domain: str) -> dict:
    """
    根据黑名单、特征和机器学习模型检测单个DNS域名是否恶意
    返回：检测结果字典
    """
    result = {
        "domain": domain,
        "is_malicious": False,
        "is_suspicious": False,
        "reason": "正常",
        "resolve_ip": None,
        "ml_prediction": None,
        "ml_confidence": 0.0
    }
    #黑名单匹配
    if domain in MALICIOUS_DOMAINS:
        result["is_malicious"] = True
        result["reason"] = "命中恶意域名黑名单"
        return result
    #可疑特征匹配
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(domain):
            result["is_suspicious"] = True
            result["reason"] = f"命中可疑特征：{pattern.pattern}"
            break
    #尝试解析IP
    try:
        ip = socket.gethostbyname(domain)
        result["resolve_ip"] = ip
    except Exception:
        result["resolve_ip"] = "解析失败"
        if not result["is_suspicious"]:
            result["is_suspicious"] = True
            result["reason"] = "域名无法解析"
    #使用机器学习模型预测
    ml_result = predict_with_ml(domain)
    if ml_result:
        result["ml_prediction"] = ml_result["is_malicious"]
        result["ml_confidence"] = ml_result["confidence"]
        #判断是否为恶意
        if ml_result["is_malicious"] and ml_result["confidence"] > 0.7:
            result["is_malicious"] = True
            result["reason"] = f"机器学习模型预测为恶意（置信度：{ml_result['confidence']:.2f}）"

    return result

#读取DNS数据文件
def load_dns_log(file_path: str = "dns_log.txt") -> list:
    domains = []
    try:
        # 根据文件扩展名判断文件类型
        if file_path.endswith(".json"):
            # 从JSON文件读取
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    if data and isinstance(data[0], str):
                        # 直接是域名列表
                        domains = data
                    elif data and isinstance(data[0], dict):
                        for item in data:
                            for key in ["domain", "name", "host", "url"]:
                                if key in item and isinstance(item[key], str):
                                    domains.append(item[key])
                                    break
        elif file_path.endswith(".csv"):
            # 从CSV文件读取
            with open(file_path, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                # 尝试从常见列名中提取域名
                for row in reader:
                    for key in ["domain", "name", "host", "url"]:
                        if key in row and row[key]:
                            domains.append(row[key])
                            break
        elif file_path.endswith(".pcapng") or file_path.endswith(".pcap"):
            #从PCAP/PCAPNG文件读取DNS查询
            try:
                packets = rdpcap(file_path)
                for packet in packets:
                    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # qr=0表示查询
                        for i in range(packet[DNS].qdcount):
                            qname = packet[DNS].qd[i].qname.decode('utf-8', errors='ignore').rstrip('.')
                            if qname:
                                domains.append(qname)
            except Exception as e:
                print(f"解析PCAP文件时出错：{e}")
        else:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.append(line)
    except FileNotFoundError:
        print(f"未找到 {file_path}")
        return []
    except Exception as e:
        print(f"读取文件 {file_path} 时出错：{e}")
        return []
    return domains
#主要部分
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
    #加载DNS记录
    dns_domains = load_dns_log(file_path)
    if not dns_domains:
        print("未加载到任何DNS记录，程序退出")
        sys.exit(0)
    print(f"\n从 {file_path} 共加载 {len(dns_domains)} 条DNS记录\n")
    #开始检测
    malicious_list = []
    suspicious_list = []
    normal_list = []
    for domain in dns_domains:
        res = check_dns_record(domain)
        #显示检测结果
        ml_info = f" | ML预测: {'恶意' if res.get('ml_prediction') else '正常'} (置信度: {res.get('ml_confidence', 0):.2f})" if res.get('ml_prediction') is not None else ""
        print(f"【检测】{domain:30} | {res['reason']}{ml_info}")
        if res["is_malicious"]:
            malicious_list.append(res)
        elif res["is_suspicious"]:
            suspicious_list.append(res)
        else:
            normal_list.append(res)
    #输出报告
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
