import socket
import re
from datetime import datetime
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
    """
    从文本文件读取DNS查询记录
    """
    domains = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
    except FileNotFoundError:
        print(f"未找到 {file_path}，将使用测试数据")
        return [
            "www.baidu.com",
            "malware-test.com",
            "random123456789abc.top",
            "fake-bank.com",
            "github.com",
            "xn--80ak6aa92e.com"
        ]
    return domains
#主要执行部分
if __name__ == "__main__":
    print(f"检测开始时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")#每次检测数据行为时的时间
    print("=" * 60)
    #加载DNS记录
    dns_domains = load_dns_log()
    print(f"\n共加载 {len(dns_domains)} 条DNS记录\n")
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