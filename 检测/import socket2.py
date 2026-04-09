import socket
import re
import json
import csv
from datetime import datetime
from scapy.all import rdpcap, DNS
# 恶意DNS域名黑名单（后面证据累积后直接加到这里）
MALICIOUS_DOMAINS = {
    "malware-test.com",
    "phishing-example.org",
    "botnet-command.cc",
    "evil-domain.ru",
    "ad-tracker.net",
    "fake-bank.com"
}
# 可疑特征（正则表达式，用于识别异常域名）
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
    根据黑名单和特征检测单个DNS域名是否恶意
    返回：检测结果字典
    """
    result = {
        "domain": domain,
        "is_malicious": False,
        "is_suspicious": False,
        "reason": "正常",
        "resolve_ip": None
    }
    # 1. 黑名单匹配（最直接的恶意判断）
    if domain in MALICIOUS_DOMAINS:
        result["is_malicious"] = True
        result["reason"] = "命中恶意域名黑名单"#显示被检测的原因
        return result
    # 2. 可疑特征匹配
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(domain):
            result["is_suspicious"] = True
            result["reason"] = f"命中可疑特征：{pattern.pattern}"#显示被检测的原因
            break
    # 3. 尝试解析IP（无法解析的域名也可能异常）
    try:
        ip = socket.gethostbyname(domain)
        result["resolve_ip"] = ip
    except Exception:
        result["resolve_ip"] = "解析失败"
        if not result["is_suspicious"]:
            result["is_suspicious"] = True
            result["reason"] = "域名无法解析"#显示被检测的原因

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
                # 支持两种JSON格式：直接是域名列表，或包含域名字段的对象列表
                if isinstance(data, list):
                    if data and isinstance(data[0], str):
                        # 直接是域名列表
                        domains = data
                    elif data and isinstance(data[0], dict):
                        # 是对象列表，尝试提取域名字段
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
            # 从PCAP/PCAPNG文件读取DNS查询
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
            # 默认按文本文件处理
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
#主要执行部分
if __name__ == "__main__":
    print(f"检测开始时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")#每次检测数据行为时的时间
    print("=" * 60)
    # 提示用户输入文件路径
    import sys
    file_path = "dns_log.txt"  # 默认文件
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        user_input = input(f"请输入DNS数据文件路径或pcapng文件路径：").strip()
        if not user_input:
            print("未输入文件路径，程序退出")
            sys.exit(0)
        # 移除可能的引号
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
        print(f"【检测】{domain:30} | {res['reason']}")
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
            print(f"  - {item['domain']} | {item['reason']}")#详细原因展示（若有）
    if suspicious_list:
        print("\n发现可疑域名：")
        for item in suspicious_list:
            print(f"  - {item['domain']} | {item['reason']}")#详细原因展示（若有）



    print(f"\n检测完成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")#显示结束时间