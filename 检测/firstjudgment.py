import re
import math
from collections import Counter
from scapy.all import rdpcap, DNS

SAFE_DOMAINS = {
    'google.com', 'baidu.com', 'qq.com', 'taobao.com', 'jd.com',
    'alibaba.com', 'tencent.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'youtube.com', 'wikipedia.org', 'baidu.cn', 'sina.com.cn',
    'sohu.com', '163.com', '126.com', 'outlook.com', 'live.com',
    'office.com', 'aliyun.com', 'cloud.tencent.com'
}

SAFE_TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil',
    '.cn', '.jp', '.de', '.uk', '.fr', '.ru', '.br',
    '.io', '.co', '.edu.cn', '.gov.cn','.top'
}

MIN_DOMAIN_ENTROPY = 2.5
MAX_DOMAIN_ENTROPY = 4.7
MAX_AVG_SUBDOMAIN_LENGTH = 35
MAX_MAX_SUBDOMAIN_LENGTH = 55
MAX_LENGTH_RATIO = 0.5
MIN_SEGMENTS = 1
MAX_SEGMENTS = 6
MAX_CONSECUTIVE_CHARS = 3
MAX_REPEAT_PATTERNS = 2

def is_base64_encoded(domain):
    clean_domain = domain.replace('.', '')
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
    return bool(base64_pattern.match(clean_domain))

def is_hex_encoded(domain):
    clean_domain = domain.replace('.', '')
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    return bool(hex_pattern.match(clean_domain)) and len(clean_domain) >= 8

def calculate_entropy(domain):
    clean_domain = domain.replace('.', '')
    if not clean_domain:
        return 0
    freq = Counter(clean_domain)
    total = len(clean_domain)
    entropy = 0
    for count in freq.values():
        probability = count / total
        if probability > 0:
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

def extract_domain_features(domain):
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

def is_safe_tld(domain):
    return any(domain.endswith(tld) for tld in SAFE_TLDS)

def is_known_safe_domain(domain):
    return domain.lower() in SAFE_DOMAINS or any(domain.lower().endswith(safe) for safe in SAFE_DOMAINS)

def quick_safety_check(domain):
    result = {
        'domain': domain,
        'is_safe': False,
        'risk_score': 0,
        'reasons': [],
        'can_skip': False
    }

    if not domain or len(domain) < 3:
        result['reasons'].append('域名过短')
        result['risk_score'] += 30
        return result

    if is_known_safe_domain(domain):
        result['is_safe'] = True
        result['can_skip'] = True
        result['reasons'].append('已知安全域名')
        return result

    if is_safe_tld(domain) and '.' in domain:
        parts = domain.split('.')
        if len(parts) >= 2:
            main_part = parts[-2]
            if len(main_part) >= 3 and len(main_part) <= 15:
                if not any(c.isdigit() for c in main_part):
                    if main_part.lower() == main_part or main_part.capitalize() == main_part:
                        result['is_safe'] = True
                        result['can_skip'] = True
                        result['reasons'].append('常规域名结构')
                        return result

    features = extract_domain_features(domain)

    if features['is_base64']:
        result['risk_score'] += 35
        result['reasons'].append('疑似Base64编码')

    if features['is_hex_encoded']:
        result['risk_score'] += 35
        result['reasons'].append('疑似十六进制编码')

    if features['domain_entropy'] < MIN_DOMAIN_ENTROPY:
        result['risk_score'] += 18
        result['reasons'].append('熵值过低')

    if features['domain_entropy'] > MAX_DOMAIN_ENTROPY:
        result['risk_score'] += 22
        result['reasons'].append('熵值过高(随机生成)')

    if features['has_long_random']:
        result['risk_score'] += 30
        result['reasons'].append('包含长随机字符串')

    if features['has_idn']:
        result['risk_score'] += 25
        result['reasons'].append('包含国际化域名')

    if features['avg_subdomain_length'] > MAX_AVG_SUBDOMAIN_LENGTH:
        result['risk_score'] += 25
        result['reasons'].append('子域名平均长度异常')

    if features['max_subdomain_length'] > MAX_MAX_SUBDOMAIN_LENGTH:
        result['risk_score'] += 30
        result['reasons'].append('子域名最大长度异常')

    if features['digit_ratio'] > MAX_LENGTH_RATIO:
        result['risk_score'] += 22
        result['reasons'].append('数字占比过高')

    if features['has_repeated_patterns']:
        result['risk_score'] += 18
        result['reasons'].append('存在重复模式')

    if features['has_consecutive_chars']:
        result['risk_score'] += 14
        result['reasons'].append('存在连续重复字符')

    if features['subdomains'] > MAX_SEGMENTS:
        result['risk_score'] += 14
        result['reasons'].append('子域名层级过多')

    if not is_safe_tld(domain):
        result['risk_score'] += 18
        result['reasons'].append('使用非常见顶级域名')

    if result['risk_score'] >= 60:
        result['can_skip'] = False
    elif result['risk_score'] < 40:
        result['can_skip'] = True
        result['is_safe'] = True

    return result

def filter_domains(domains, skip_safe=True, min_risk_score=50):
    results = []
    safe_count = 0
    risky_count = 0

    for domain in domains:
        check_result = quick_safety_check(domain)

        if skip_safe and check_result['can_skip']:
            safe_count += 1
            continue

        if check_result['risk_score'] >= min_risk_score:
            risky_count += 1

        results.append(check_result)

    return results, {'safe_filtered': safe_count, 'risky': risky_count}

def extract_domains_from_pcap(file_path):
    domains = []
    file_path = file_path.strip('"').strip("'")
    try:
        packets = rdpcap(file_path)
        for packet in packets:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                for i in range(packet[DNS].qdcount):
                    qname = packet[DNS].qd[i].qname.decode('utf-8', errors='ignore').rstrip('.')
                    if qname and qname not in domains:
                        domains.append(qname)
    except Exception as e:
        print(f"解析PCAP文件时出错: {e}")
        return []
    return domains

def batch_check(file_path, skip_safe=True):
    domains = []
    file_path = file_path.strip('"').strip("'")

    if file_path.endswith('.pcap') or file_path.endswith('.pcapng'):
        print(f"正在从PCAP文件提取DNS域名...")
        domains = extract_domains_from_pcap(file_path)
    else:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domains.append(line)
        except FileNotFoundError:
            print(f"文件未找到: {file_path}")
            return []
        except Exception as e:
            print(f"读取文件出错: {e}")
            return []

    results, stats = filter_domains(domains, skip_safe=skip_safe)

    print(f"\n=== 初步过滤结果 ===")
    print(f"总域名数: {len(domains)}")
    print(f"安全过滤: {stats['safe_filtered']} 个")
    print(f"需进一步检测: {stats['risky']} 个")

    return results

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        file_path = sys.argv[1].strip('"').strip("'")
    else:
        file_path = input("请输入域名文件或PCAP文件路径: ").strip().strip('"').strip("'")

    results = batch_check(file_path, skip_safe=True)

    if results:
        print(f"\n=== 需检测的域名 ({len(results)}个) ===")
        for r in results[:20]:
            print(f"[风险:{r['risk_score']:3d}] {r['domain']:40} | {', '.join(r['reasons']) if r['reasons'] else '正常'}")
        if len(results) > 20:
            print(f"... 还有 {len(results) - 20} 个域名")
