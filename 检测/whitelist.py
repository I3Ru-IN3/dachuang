
"""
白名单配置文件
用于DNS隧道检测的白名单域名过滤
使用 from whitelist import SAFE_DOMAINS, safe_domain 进行引用
"""

# 安全域名白名单
SAFE_DOMAINS = {
    'google.com', 'baidu.com', 'qq.com', 'taobao.com', 'jd.com',
    'alibaba.com', 'tencent.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'youtube.com', 'wikipedia.org', 'baidu.cn', 'sina.com.cn',
    'sohu.com', '163.com','outlook.com', 'live.com',
    'office.com', 'aliyun.com', 'cloud.tencent.com'
}


def safe_domain(domain):
    """检查域名是否在安全域名白名单中"""
    return domain.lower() in SAFE_DOMAINS or any(domain.lower().endswith(safe) for safe in SAFE_DOMAINS)

