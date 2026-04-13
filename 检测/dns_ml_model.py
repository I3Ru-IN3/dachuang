import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
import joblib
import re
from scapy.all import rdpcap, DNS
import json

# 域名特征提取函数
def extract_features(domain):
    features = {}
    # 域名长度
    features['length'] = len(domain)
    # 数字比例
    features['digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
    # 特殊字符数量
    features['special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', domain))
    # 子域名数量
    features['subdomains'] = domain.count('.')
    # 是否包含长随机字符串
    features['has_long_random'] = 1 if re.search(r'[a-z0-9]{15,}', domain) else 0
    # 是否包含国际化域名标记
    features['has_idn'] = 1 if 'xn--' in domain else 0
    # 顶级域名
    tld = domain.split('.')[-1] if '.' in domain else domain
    features['tld'] = tld
    return features

# 从pcapng文件读取DNS域名
def load_domains_from_pcapng(pcapng_file):
    domains = []
    try:
        packets = rdpcap(pcapng_file)
        for packet in packets:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                for i in range(packet[DNS].qdcount):
                    qname = packet[DNS].qd[i].qname.decode('utf-8', errors='ignore').rstrip('.')
                    if qname:
                        domains.append(qname)
    except Exception as e:
        print(f"解析PCAPNG文件时出错：{e}")
    return domains

# 从标注文件加载已标注的域名数据
def load_labeled_domains(label_file):
    labeled_data = []
    try:
        with open(label_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for item in data:
                if isinstance(item, dict) and 'domain' in item and 'label' in item:
                    labeled_data.append((item['domain'], item['label']))
    except FileNotFoundError:
        print(f"标注文件 {label_file} 不存在")
    except Exception as e:
        print(f"读取标注文件时出错：{e}")
    return labeled_data

# 交互式标注域名
def interactive_labeling(domains):
    labeled_data = []
    print(f"开始交互式标注，共有 {len(domains)} 个域名")
    print("输入 0 表示正常域名，1 表示恶意域名，q 退出标注")
    
    for i, domain in enumerate(domains):
        while True:
            user_input = input(f"域名 [{i+1}/{len(domains)}] {domain} (0/1/q): ").strip().lower()
            if user_input == 'q':
                print(f"标注完成，共标注 {len(labeled_data)} 个域名")
                return labeled_data
            elif user_input in ['0', '1']:
                label = int(user_input)
                labeled_data.append((domain, label))
                break
            else:
                print("无效输入，请输入 0、1 或 q")
    
    return labeled_data

# 保存标注数据
def save_labeled_data(labeled_data, output_file):
    data = [{'domain': domain, 'label': label} for domain, label in labeled_data]
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"标注数据已保存到 {output_file}")
    except Exception as e:
        print(f"保存标注数据时出错：{e}")

# 准备数据集
def prepare_dataset(labeled_data=None):
    # 如果没有提供标注数据，使用默认的标注数据集
    if labeled_data is None:
        data = [
            # 正常域名
            ('www.baidu.com', 0),
            ('www.google.com', 0),
            ('github.com', 0),
            ('www.microsoft.com', 0),
            ('www.apple.com', 0),
            ('www.amazon.com', 0),
            ('www.taobao.com', 0),
            ('www.jd.com', 0),
            ('www.qq.com', 0),
            ('www.weibo.com', 0),
            # 恶意域名
            ('malware-test.com', 1),
            ('phishing-example.org', 1),
            ('botnet-command.cc', 1),
            ('evil-domain.ru', 1),
            ('ad-tracker.net', 1),
            ('fake-bank.com', 1),
            ('random123456789abc.top', 1),
            ('xn--80ak6aa92e.com', 1),
            ('123456789012345.com', 1),
            ('malicious-site.work', 1)
        ]
    else:
        data = labeled_data
    
    # 转换为DataFrame
    df = pd.DataFrame(data, columns=['domain', 'label'])
    # 提取特征
    features = []
    for domain in df['domain']:
        feat = extract_features(domain)
        features.append(feat)
    # 转换特征为DataFrame
    features_df = pd.DataFrame(features)
    # 合并特征和标签
    final_df = pd.concat([df, features_df], axis=1)
    # 只使用数值特征，避免TLD编码问题
    numeric_features = ['length', 'digit_ratio', 'special_chars', 'subdomains', 'has_long_random', 'has_idn']
    final_df = final_df[['domain', 'label'] + numeric_features]
    return final_df
# 训练模型
def train_model(labeled_data=None):
    # 准备数据
    df = prepare_dataset(labeled_data)
    # 特征和标签
    X = df.drop(['domain', 'label'], axis=1)
    y = df['label']
    # 分割训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    # 创建并训练模型
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    # 测试模型
    y_pred = model.predict(X_test)
    print("分类报告：")
    print(classification_report(y_test, y_pred))
    print("混淆矩阵：")
    print(confusion_matrix(y_test, y_pred))
    # 保存模型
    joblib.dump(model, 'dns_malware_model.pkl')
    print("模型已保存为 dns_malware_model.pkl")
    return model

# 从pcapng文件训练模型的完整流程
def train_from_pcapng(pcapng_file, label_file=None, auto_label=False):
    # 1. 从pcapng文件加载域名
    print(f"正在从 {pcapng_file} 加载域名...")
    domains = load_domains_from_pcapng(pcapng_file)
    
    if not domains:
        print("未从pcapng文件中提取到任何域名")
        return None
    
    print(f"成功提取 {len(domains)} 个域名")
    
    # 2. 域名去重
    domains = list(set(domains))
    print(f"去重后剩余 {len(domains)} 个唯一域名")
    
    # 3. 标注域名
    labeled_data = None
    
    if label_file:
        # 尝试从标注文件加载
        labeled_data = load_labeled_domains(label_file)
        if labeled_data:
            print(f"从标注文件加载了 {len(labeled_data)} 个已标注域名")
        else:
            print("标注文件不存在或为空，将进行交互式标注")
    
    if not labeled_data:
        if auto_label:
            # 自动标注（基于黑名单和特征）
            print("正在进行自动标注...")
            labeled_data = auto_label_domains(domains)
        else:
            # 交互式标注
            labeled_data = interactive_labeling(domains)
            
            # 保存标注结果
            if labeled_data:
                save_labeled_data(labeled_data, 'dns_labels.json')
    
    if not labeled_data or len(labeled_data) < 10:
        print("警告：标注数据不足，将使用默认数据集")
        labeled_data = None
    
    # 4. 训练模型
    print("\n开始训练模型...")
    model = train_model(labeled_data)
    
    return model

# 自动标注域名（基于黑名单和特征）
def auto_label_domains(domains):
    # 恶意域名黑名单
    MALICIOUS_DOMAINS = {
        "malware-test.com",
        "phishing-example.org",
        "botnet-command.cc",
        "evil-domain.ru",
        "ad-tracker.net",
        "fake-bank.com"
    }
    
    # 可疑特征
    SUSPICIOUS_PATTERNS = [
        re.compile(r'\d{5,}'),
        re.compile(r'[a-z0-9]{20,}'),
        re.compile(r'xn--'),
        re.compile(r'\.top$'),
        re.compile(r'\.work$'),
        re.compile(r'\.club$')
    ]
    
    labeled_data = []
    for domain in domains:
        # 检查黑名单
        if domain in MALICIOUS_DOMAINS:
            labeled_data.append((domain, 1))
            continue
        
        # 检查可疑特征
        is_suspicious = False
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.search(domain):
                is_suspicious = True
                break
        
        if is_suspicious:
            labeled_data.append((domain, 1))
        else:
            labeled_data.append((domain, 0))
    
    print(f"自动标注完成：正常域名 {sum(1 for _, label in labeled_data if label == 0)} 个，恶意域名 {sum(1 for _, label in labeled_data if label == 1)} 个")
    return labeled_data
# 加载模型
def load_model():
    try:
        model = joblib.load('dns_malware_model.pkl')
        return model
    except FileNotFoundError:
        print("模型文件不存在，正在搭建新模型...")
        return train_model()
# 预测函数
def predict_domain(model, domain):
    # 提取特征
    feat = extract_features(domain)
    # 转换为DataFrame
    feat_df = pd.DataFrame([feat])
    # 处理分类特征（TLD）
    # 手动创建与训练时一致的特征列
    # 先只使用数值特征，避免TLD编码问题
    numeric_features = ['length', 'digit_ratio', 'special_chars', 'subdomains', 'has_long_random', 'has_idn']
    # 确保只包含数值特征
    feat_df = feat_df[numeric_features]
    # 预测
    prediction = model.predict(feat_df)[0]
    probability = model.predict_proba(feat_df)[0][1]
    return {
        'domain': domain,
        'is_malicious': bool(prediction),
        'confidence': probability
    }
if __name__ == "__main__":
    import sys
    
    # 检查命令行参数
    if len(sys.argv) > 1 and sys.argv[1] == "--pcapng":
        # 使用pcapng文件训练模型
        if len(sys.argv) < 3:
            print("使用方法：python dns_ml_model.py --pcapng <pcapng文件> [--label <标注文件>] [--auto]")
            print("  --pcapng: 指定pcapng文件路径")
            print("  --label:  指定标注文件路径（可选）")
            print("  --auto:   使用自动标注（可选）")
            sys.exit(1)
        
        pcapng_file = sys.argv[2]
        label_file = None
        auto_label = False
        
        # 解析可选参数
        for i in range(3, len(sys.argv)):
            if sys.argv[i] == "--label" and i + 1 < len(sys.argv):
                label_file = sys.argv[i + 1]
            elif sys.argv[i] == "--auto":
                auto_label = True
        
        # 从pcapng文件训练模型
        model = train_from_pcapng(pcapng_file, label_file, auto_label)
        
        if model:
            print("\n模型训练完成！")
        else:
            print("\n模型训练失败！")
    else:
        # 训练模型（使用默认数据集）
        model = train_model()
        # 测试预测
        test_domains = [
            'www.baidu.com',
            'malware-test.com',
            'random123456789abc.top',
            'github.com',
            'xn--80ak6aa92e.com'
        ]
        print("\n测试预测结果：")
        for domain in test_domains:
            result = predict_domain(model, domain)
            print(f"域名: {domain}")
            print(f"是否恶意: {'是' if result['is_malicious'] else '否'}")
            print(f"置信度: {result['confidence']:.2f}")
            print()