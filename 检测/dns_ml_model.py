import argparse
import os
import sys
import re
import math
import json
import csv
from collections import Counter

import numpy as np
from scapy.all import rdpcap, DNS, DNSQR
import joblib
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

USE_SOCKET4_FEATURES = False
USE_JUDGMENT = False

# 尝试加载 firstjudgment.py 用于初步研判
try:
    import importlib.machinery
    judgment_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'firstjudgment.py')
    if os.path.exists(judgment_path):
        loader = importlib.machinery.SourceFileLoader('judgment_module', judgment_path)
        judgment_module = loader.load_module()
        USE_JUDGMENT = True

    else:
        print(f"错误: 未找到 firstjudgment.py")
except Exception as e:
    print(f"错误: 加载 firstjudgment.py 失败: {e}")

# 尝试加载 import socket4.py 用于精密研判
try:
    socket4_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'import socket4.py')
    if os.path.exists(socket4_path):
        loader = importlib.machinery.SourceFileLoader('socket4_module', socket4_path)
        socket4_module = loader.load_module()
        USE_SOCKET4_FEATURES = True

    else:
        print(f"错误: 未找到 import socket4.py")
except Exception as e:
    print(f"错误: 加载 import socket4.py 失败: {e}")

FEATURE_NAMES = [
    'length', 'digit_ratio', 'special_chars', 'subdomains',
    'has_long_random', 'has_idn', 'is_base64', 'is_hex_encoded',
    'avg_subdomain_length', 'max_subdomain_length', 'domain_entropy',
    'has_repeated_patterns', 'has_consecutive_chars'
]

class OnlineLearningBuffer:
    """在线学习样本缓冲区"""
    
    def __init__(self, threshold=10):
        self.threshold = threshold
        self.normal_samples = []
        self.malicious_samples = []
        self.normal_features = []
        self.malicious_features = []
    
    def add_sample(self, domain, features, is_malicious):
        feature_vector = np.array(list(features.values())) if hasattr(features, 'values') else np.array(features)
        if is_malicious:
            self.malicious_samples.append(domain)
            self.malicious_features.append(feature_vector)
        else:
            self.normal_samples.append(domain)
            self.normal_features.append(feature_vector)
    
    def should_update(self):
        return len(self.normal_features) >= self.threshold // 2 or len(self.malicious_features) >= self.threshold // 2
    
    def get_samples(self):
        all_features = self.normal_features + self.malicious_features
        all_labels = [0] * len(self.normal_features) + [1] * len(self.malicious_features)
        return np.array(all_features), np.array(all_labels)
    
    def clear(self):
        self.normal_samples.clear()
        self.malicious_samples.clear()
        self.normal_features.clear()
        self.malicious_features.clear()
    
    def get_count(self):
        return {
            'normal': len(self.normal_samples),
            'malicious': len(self.malicious_samples),
            'total': len(self.normal_samples) + len(self.malicious_samples)
        }

def online_update_model(model, scaler, buffer, model_path):
    """在线更新模型"""
    if not buffer.should_update():
        return model, scaler
    
    print(f"\n[在线学习] 检测到 {buffer.get_count()['total']} 个新样本，开始增量学习...")
    
    try:
        X_new, y_new = buffer.get_samples()
        if len(X_new.shape) == 1:
            X_new = X_new.reshape(1, -1)
        X_new_scaled = scaler.transform(X_new)
        model.partial_fit(X_new_scaled, y_new, classes=np.array([0, 1]))
        joblib.dump((model, scaler), model_path)
        print(f"[在线学习] 模型已更新并保存到: {model_path}")
        buffer.clear()
        return model, scaler
    except Exception as e:
        print(f"[在线学习] 更新失败: {e}")
        return model, scaler

def extract_domain_features(domain):
    """提取域名特征用于机器学习"""
    features = {}
    features['length'] = len(domain)
    features['digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
    features['special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', domain))
    features['subdomains'] = domain.count('.')
    features['has_long_random'] = 1 if re.search(r'[a-z0-9]{15,}', domain) else 0
    features['has_idn'] = 1 if 'xn--' in domain else 0
    
    # Base64检测
    clean_domain = domain.replace('.', '').replace('-', '').replace('_', '')
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
    features['is_base64'] = 1 if len(clean_domain) % 4 == 0 and base64_pattern.match(clean_domain) else 0
    
    # 十六进制检测
    clean_domain_hex = domain.replace('.', '').replace('-', '')
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    features['is_hex_encoded'] = 1 if hex_pattern.match(clean_domain_hex) and len(clean_domain_hex) >= 8 else 0
    
    # 子域名长度
    parts = domain.split('.')
    if len(parts) <= 1:
        features['avg_subdomain_length'] = 0.0
        features['max_subdomain_length'] = 0.0
    else:
        features['avg_subdomain_length'] = np.mean([len(p) for p in parts[:-1]])
        features['max_subdomain_length'] = max([len(p) for p in parts[:-1]])
    
    # 熵值计算
    if not domain:
        features['domain_entropy'] = 0.0
    else:
        freq = Counter(domain)
        total = len(domain)
        entropy = 0.0
        for count in freq.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        features['domain_entropy'] = entropy
    
    features['has_repeated_patterns'] = 1 if re.search(r'(.{3,})\1{2,}', domain) else 0
    features['has_consecutive_chars'] = 1 if re.search(r'(.)\1{3,}', domain) else 0
    
    return features

def rapid_analysis(domain):
    """
    初步研判：快速筛选安全度高的DNS流量
    使用 firstjudgment.py 进行研判
    """
    if USE_JUDGMENT:
        result = judgment_module.quick_safety_check(domain)
        return {
            'is_safe': result['is_safe'],
            'safety_score': 100 - result['risk_score'],
            'reasons': result['reasons'],
            'can_skip': result.get('can_skip', False)
        }
    else:
        raise Exception("未加载 firstjudgment.py ")

def batch_rapid_filter(domains):
    """
    批量初步研判筛选
    使用 firstjudgment.py 进行研判
    """
    if USE_JUDGMENT:
        results, stats = judgment_module.filter_domains(domains, skip_safe=False)
        safe_domains = []
        suspicious_domains = []
        
        for result in results:
            result['safety_score'] = 100 - result['risk_score']
            result['is_safe'] = result['safety_score'] >= 60
            
            if result['is_safe']:
                safe_domains.append(result)
            else:
                suspicious_domains.append(result)
        
        return {
            'safe_domains': safe_domains,
            'suspicious_domains': suspicious_domains,
            'filtered_count': len(safe_domains),
            'remaining_count': len(suspicious_domains),
            'total_count': len(domains),
            'filter_rate': len(safe_domains) / len(domains) * 100
        }
    else:
        raise Exception("未加载 firstjudgment.py ")

def load_pcap_domains(pcap_path):
    domains = []
    try:
        packets = rdpcap(pcap_path)
        for packet in packets:
            if DNS in packet and packet[DNS].qr == 0:
                qd = packet[DNS].qd
                if qd and qd.qname:
                    domain = qd.qname.decode('utf-8').rstrip('.')
                    domains.append(domain)
        return list(set(domains))
    except Exception as e:
        print(f"Error loading PCAP: {e}")
        return []

def load_domain_file(file_path, with_label=False):
    """
    加载域名文件
    :param file_path: 文件路径
    :param with_label: 是否返回带label的数据（CSV格式，第二列为label）
    :return: 域名列表 或 包含(domain, label)的元组列表
    """
    domains = []
    labels = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # 处理CSV格式
                    if ',' in line:
                        parts = line.split(',')
                        domain = parts[0].strip()
                        if domain:
                            # 跳过表头
                            if domain.lower() == 'domain' and len(parts) > 1 and parts[1].lower() == 'length':
                                continue
                            domains.append(domain)
                            if with_label and len(parts) >= 2:
                                try:
                                    # 取最后一列作为label
                                    labels.append(int(parts[-1].strip()))
                                except:
                                    labels.append(0)
                            elif with_label:
                                labels.append(0)
                    else:
                        domain = line
                        if domain:
                            domains.append(domain)
                            if with_label:
                                labels.append(0)
        if with_label:
            return list(zip(domains, labels))
        return domains
    except Exception as e:
        print(f"Error loading file: {e}")
        return [] if not with_label else []

def predict_with_model(domain, model, scaler):
    """使用模型进行预测"""
    features = extract_domain_features(domain)
    feature_vector = [features.get(name, 0.0) for name in FEATURE_NAMES]
    feature_vector = np.array(feature_vector).reshape(1, -1)
    feature_scaled = scaler.transform(feature_vector)
    
    prediction = model.predict(feature_scaled)[0]
    confidence = model.predict_proba(feature_scaled)[0]
    
    return {
        'prediction': prediction,
        'confidence': confidence,
        'malicious_prob': confidence[1],
        'normal_prob': confidence[0]
    }

def load_pcap_domains_with_timestamps(pcap_path):
    records = []
    try:
        packets = rdpcap(pcap_path)
        for packet in packets:
            if DNS in packet and packet[DNS].qr == 0:
                qd = packet[DNS].qd
                if qd and qd.qname:
                    domain = qd.qname.decode('utf-8').rstrip('.')
                    timestamp = float(packet.time)
                    records.append({
                        'domain': domain,
                        'timestamp': timestamp,
                        'qtype': qd.qtype if hasattr(qd, 'qtype') else 1
                    })
        return records
    except Exception as e:
        print(f"Error loading PCAP: {e}")
        return []
def generate_training_data(pcap_path, output_csv, label=1):
    """从PCAP文件生成训练数据"""
    print(f"正在从PCAP文件生成训练数据: {pcap_path}")
    records = load_pcap_domains_with_timestamps(pcap_path)
    if not records:
        print("未找到DNS记录")
        return
    
    domains = list(set([r['domain'] for r in records]))
    print(f"发现 {len(domains)} 个唯一域名")
    
    with open(output_csv, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['domain'] + FEATURE_NAMES + ['label'])
        for domain in domains:
            features = extract_domain_features(domain)
            feature_values = [features.get(f, 0) for f in FEATURE_NAMES]
            writer.writerow([domain] + feature_values + [label])
    
    print(f"训练数据已保存到: {output_csv}")
    return domains

def train_model(train_data_path, model_path):
    """训练机器学习模型"""
    import pandas as pd
    
    print(f"加载训练数据: {train_data_path}")
    try:
        df = pd.read_csv(train_data_path)
    except Exception as e:
        print(f"加载训练数据失败: {e}")
        return
    
    # 检查特征列是否存在
    missing_features = [f for f in FEATURE_NAMES if f not in df.columns]
    if missing_features:
        print(f"错误: 缺少以下特征列: {missing_features}")
        print(f"CSV文件包含的列: {list(df.columns)}")
        return
    
    X = df[FEATURE_NAMES].values
    y = df['label'].values
    
    print(f"训练样本数: {len(y)}")
    print(f"恶意样本: {sum(y)} ({sum(y)/len(y)*100:.2f}%)")
    print(f"正常样本: {len(y)-sum(y)} ({(len(y)-sum(y))/len(y)*100:.2f}%)")
    
    # 检查是否有缺失值
    if df[FEATURE_NAMES].isnull().any().any():
        print("警告: 数据中存在缺失值，将进行填充")
        df[FEATURE_NAMES] = df[FEATURE_NAMES].fillna(0)
        X = df[FEATURE_NAMES].values
    
    # 检查数据类型
    print(f"\n特征数据类型: {X.dtype}")
    print(f"标签数据类型: {y.dtype}")
    
    # 标准化特征
    scaler = StandardScaler()
    try:
        X_scaled = scaler.fit_transform(X)
    except Exception as e:
        print(f"特征标准化失败: {e}")
        return
    
    print(f"\n特征维度: {X_scaled.shape}")
    
    # 训练 SGD 分类器（支持在线学习）
    print("\n训练 SGD 分类器...")
    model = SGDClassifier(
        loss='log_loss',  # 逻辑回归，支持概率输出
        penalty='l2',
        alpha=0.0001,
        max_iter=1000,
        tol=1e-3,
        random_state=42
    )
    
    try:
        model.fit(X_scaled, y)
    except Exception as e:
        print(f"模型训练失败: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # 保存模型
    joblib.dump((model, scaler), model_path)
    print(f"\n模型已保存到: {model_path}")
    
    # 特征系数（权重）
    print("\n【特征权重】")
    coefficients = model.coef_[0]
    indices = np.argsort(np.abs(coefficients))[::-1]
    for f in range(len(FEATURE_NAMES)):
        idx = indices[f]
        print(f"{f+1}. {FEATURE_NAMES[idx]}: {coefficients[idx]:.4f}")
    
    return model, scaler

def run_model_inference(domains, model_path):
    """运行模型推理"""
    import joblib
    try:
        model, scaler = joblib.load(model_path)
    except Exception as e:
        print(f"加载模型失败: {e}")
        return
    
    print("\n【机器学习模型推理】")
    print(f"域名数量: {len(domains)}")
    print(f"模型文件: {model_path}")
    print("\n{:<50} {:<10} {:<15} {:<15}".format("域名", "结果", "恶意概率", "正常概率"))
    print("-"*80)
    
    malicious_count = 0
    normal_count = 0
    
    for domain in domains:
        result = predict_with_model(domain, model, scaler)
        label = "恶意" if result['prediction'] == 1 else "正常"
        
        if result['prediction'] == 1:
            malicious_count += 1
        else:
            normal_count += 1
        
        print("{:<50} {:<10} {:<15.4f} {:<15.4f}".format(
            domain[:48], label, result['malicious_prob'], result['normal_prob']
        ))
    
    print("\n推理结果汇总:")
    print(f"  恶意域名: {malicious_count} ({malicious_count/len(domains)*100:.2f}%)")
    print(f"  正常域名: {normal_count} ({normal_count/len(domains)*100:.2f}%)")

def main():
    parser = argparse.ArgumentParser(description='DNS隧道检测')
    parser.add_argument('--two-stage', action='store_true', help='使用检测流程：初步研判筛选 -> 精密研判')
    parser.add_argument('--input', help='导入外部PCAP/PCAPNG/CSV/TXT文件进行检测')
    parser.add_argument('--detect', action='store_true', help='执行检测模式（与--input配合使用）')
    parser.add_argument('--online-learn', action='store_true', help='启用在线学习模式')
    parser.add_argument('--learn-threshold', type=int, default=10, help='在线学习触发阈值')
    parser.add_argument('--model', default='dns_ml_model.pkl', help='模型保存/加载路径')
    parser.add_argument('--generate', help='从PCAP文件生成训练数据')
    parser.add_argument('--train', help='使用CSV训练数据训练模型')
    parser.add_argument('--label', type=int, default=1, help='生成训练数据时的标签(0=正常,1=恶意)')
    parser.add_argument('--output', default='dns_training_data.csv', help='训练数据输出路径')
    parser.add_argument('--judge', help='待检测的域名、文件或PCAP路径')
    parser.add_argument('--inference', help='使用机器学习模型进行推理（域名、文件或PCAP）')
    
    args = parser.parse_args()
    
    # 生成训练数据（优先执行）
    if args.generate:
        generate_training_data(args.generate, args.output, args.label)
        return
    
    # 训练模型（优先执行）
    if args.train:
        train_model(args.train, args.model)
        return
    
    # 模型推理（优先执行）
    if args.inference:
        inference_input = args.inference.strip('"').strip("'")
        domains = []
        if os.path.exists(inference_input):
            ext = inference_input.lower()
            if ext.endswith('.pcap') or ext.endswith('.pcapng'):
                domains = load_pcap_domains(inference_input)
            else:
                domains = load_domain_file(inference_input)
        else:
            domains = [inference_input]
        
        if not domains:
            print("未找到待推理域名")
            return
        
        run_model_inference(domains, args.model)
        return
    
    if args.input:
        input_path = args.input.strip('"').strip("'")
        if not os.path.exists(input_path):
            print(f"文件不存在: {input_path}")
            return
        
        ext = input_path.lower()
        dns_records = []
        domains = []
        domain_labels = {}  # 存储域名的真实label
        
        if ext.endswith('.pcap') or ext.endswith('.pcapng'):
            print(f"正在从PCAP文件提取DNS记录: {input_path}")
            dns_records = load_pcap_domains_with_timestamps(input_path)
            domains = [r['domain'] for r in dns_records]
        elif ext.endswith('.csv'):
            print(f"正在从CSV文件读取域名: {input_path}")
            # 尝试读取带label的数据
            domain_with_labels = load_domain_file(input_path, with_label=True)
            if domain_with_labels:
                domains = [d[0] for d in domain_with_labels]
                domain_labels = {d[0]: d[1] for d in domain_with_labels}
                print(f"已加载 {len(domain_labels)} 个带标签的域名")
            else:
                domains = load_domain_file(input_path)
        elif ext.endswith('.txt'):
            print(f"正在从TXT文件读取域名: {input_path}")
            domains = load_domain_file(input_path)
        else:
            print(f"不支持的文件格式: {ext}")
            return
        
        if not domains:
            print("未找到待检测域名")
            return
        
        unique_domains = list(set(domains))
        print(f"提取到 {len(dns_records)} 条DNS记录，{len(unique_domains)} 个唯一域名")
        
        if args.detect:
            filter_result = batch_rapid_filter(unique_domains)
            
            print(f"\n初步研判完成:")
            print(f"  总域名数: {filter_result['total_count']}")
            print(f"  安全域名: {filter_result['filtered_count']} ({filter_result['filter_rate']:.1f}%)")
            print(f"  可疑域名: {filter_result['remaining_count']}")
            
            if not filter_result['suspicious_domains']:
                print("\n【检测完成】所有域名均为安全")
                return
            
            # 检查是否有import socket4.py模块
            if not USE_SOCKET4_FEATURES:
                print("\n错误: 未找到import socket4.py模块，无法进行精密研判")
                return

            print("【精密研判】")

            
            # 初始化在线学习
            model = None
            scaler = None
            learning_buffer = None
            if args.online_learn:
                learning_buffer = OnlineLearningBuffer(threshold=args.learn_threshold)
                try:
                    model, scaler = joblib.load(args.model)
                    print(f"[在线学习] 已加载模型: {args.model}")
                except Exception as e:
                    print(f"[在线学习] 未找到模型文件 {args.model}，跳过在线学习")
                    args.online_learn = False
            
            # 获取suspicious domains
            suspicious_domains_list = [s['domain'] for s in filter_result['suspicious_domains']]
            
            # 筛选出相关的DNS记录用于socket4.py检测
            relevant_records = [r for r in dns_records if r['domain'] in suspicious_domains_list]
            
            print("正在进行多维度检测...")
            
            # 1. 频率异常检测
            print("\n1. 频率异常检测...")
            freq_result = socket4_module.detect_frequency_anomaly(relevant_records)
            if freq_result['has_anomaly']:
                print(f"   [告警] 异常类型: {freq_result['anomaly_type']}")
                print(f"   详情: {freq_result['details']}")
                if freq_result['suspicious_domains']:
                    print(f"   高频访问域名:")
                    for domain, count in freq_result['suspicious_domains']:
                        print(f"     - {domain}: {count}次")
            else:
                print("   [通过]")
            
            # 2. 访问对象异常检测
            print("\n2. 访问对象异常检测...")
            access_result = socket4_module.detect_access_pattern_anomaly(relevant_records)
            if access_result['has_anomaly']:
                print(f"   [告警] 异常类型: {', '.join(access_result['anomaly_types'])}")
                for item in access_result['high_risk_domains']:
                    print(f"   - 高危域名: {item['domain']} ({item['reason']})")
            else:
                print("   [通过]")
            
            # 3. 响应异常检测
            print("\n3. 响应异常检测...")
            response_result = socket4_module.detect_response_anomaly(relevant_records)
            if response_result['has_anomaly']:
                print(f"   [告警] 异常类型: {', '.join(response_result['anomaly_types'])}")
                if response_result['internal_ip_responses']:
                    for item in response_result['internal_ip_responses'][:3]:
                        print(f"   - {item['domain']} -> {item['ip']} ({item['reason']})")
            else:
                print("   [通过]")
            
            # 4. 记录类型异常检测
            print("\n4. 记录类型异常检测...")
            type_result = socket4_module.detect_record_type_anomaly(relevant_records)
            if type_result['has_anomaly']:
                print(f"   [告警] 异常类型: {', '.join(type_result['anomaly_types'])}")
                if type_result['heavy_type_records']:
                    for rec in type_result['heavy_type_records']:
                        print(f"   - {rec['type_name']}: {rec['count']}次")
            else:
                print("   [通过]")
            
            # 5. 单个域名详细检测
            
            malicious_domains = []
            suspicious_domains = []
            normal_domains = []
            
            # 收集预测统计数据
            pres = []
            ml_true_labels = []
            ml_correct_count = 0
            
            for domain in suspicious_domains_list:
                res = socket4_module.check_dns_record(domain)
                
                # 在线学习：将检测结果添加到学习缓冲区
                if args.online_learn and model is not None:
                    features = extract_domain_features(domain)
                    feature_vector = [features.get(f, 0) for f in FEATURE_NAMES]
                    is_malicious = res["is_malicious"]
                    learning_buffer.add_sample(domain, feature_vector, is_malicious)
                    # 检查是否需要更新模型
                    model, scaler = online_update_model(model, scaler, learning_buffer, args.model)
                
                if res["is_malicious"]:
                    status = "[恶意]"
                    malicious_domains.append(res)
                    final_label = 1
                elif res["is_suspicious"]:
                    status = "[可疑]"
                    suspicious_domains.append(res)
                    final_label = 1
                else:
                    status = "[正常]"
                    normal_domains.append(res)
                    final_label = 0
                
                # 获取真实label（如果存在）
                true_label = domain_labels.get(domain)
                
                # 收集预测数据用于准确度计算
                if res.get('ml_prediction') is not None:
                    pres.append(res['ml_prediction'])
                    ml_true_labels.append(true_label)
                    # 比较ML预测与真实label
                    if true_label is not None and res['ml_prediction'] == true_label:
                        ml_correct_count += 1
                
                print(f"{domain:<45} {status:<10} {res['reason']}")
            
            # 总结报告
            print("\n【检测总结】")
            print(f"总域名数: {filter_result['total_count']}")
            print(f"初步筛选安全: {filter_result['filtered_count']}")
            print(f"精密研判: {len(suspicious_domains_list)}")
            print(f"  - 恶意域名: {len(malicious_domains)}")
            print(f"  - 可疑域名: {len(suspicious_domains)}")
            print(f"  - 正常域名: {len(normal_domains)}")
            
            # 检测率统计
            total = filter_result['total_count']
            if total > 0:
                malicious_rate = len(malicious_domains) / total * 100
                suspicious_rate = len(suspicious_domains) / total * 100
                normal_rate = len(normal_domains) / total * 100
                filtered_rate = filter_result['filtered_count'] / total * 100
                
                print(f"\n【检测率统计】")
                print(f"恶意域名率: {malicious_rate:.2f}%")
                print(f"可疑域名率: {suspicious_rate:.2f}%")
                print(f"正常域名率: {normal_rate:.2f}%")
                print(f"初步筛选率: {filtered_rate:.2f}%")
            
            if malicious_domains:
                print(f"\n发现{len(malicious_domains)}个恶意域名:")
                for item in malicious_domains:
                    print(f"  - {item['domain']}: {item['reason']}")
            
            # 输出研判准确度统计（放在最后）
            if pres:
                labeled_count = sum(1 for l in ml_true_labels if l is not None)
                if labeled_count > 0:
                    ml_accuracy = ml_correct_count / labeled_count * 100
                    print(f"\n【研判准确度】: {ml_accuracy:.2f}%")
        return
    
    if args.judge:
        domains = []
        domain_labels = {}  # 存储域名的真实label
        
        if os.path.isfile(args.judge):
            ext = args.judge.lower()
            if ext.endswith('.pcap') or ext.endswith('.pcapng'):
                domains = load_domain_file(args.judge)
                if not domains:
                    domains = load_pcap_domains(args.judge)
            elif ext.endswith('.csv'):
                # 尝试读取带label的数据
                domain_with_labels = load_domain_file(args.judge, with_label=True)
                if domain_with_labels:
                    domains = [d[0] for d in domain_with_labels]
                    domain_labels = {d[0]: d[1] for d in domain_with_labels}
                    print(f"已加载 {len(domain_labels)} 个带标签的域名")
                else:
                    domains = load_domain_file(args.judge)
            else:
                domains = load_domain_file(args.judge)
        else:
            domains = [args.judge]
        
        if not domains:
            print("未找到待检测域名")
            return
        
        print(f"待检测域名数: {len(domains)}")
        
        if args.two_stage:
            print("\n【第一阶段：初步研判筛选】")
            
            filter_result = batch_rapid_filter(domains)
            
            print(f"\n初步研判完成:")
            print(f"  总域名数: {filter_result['total_count']}")
            print(f"  安全域名: {filter_result['filtered_count']} ({filter_result['filter_rate']:.1f}%)")
            print(f"  可疑域名: {filter_result['remaining_count']}")
            
            if not filter_result['suspicious_domains']:
                print("\n【检测完成】所有域名均为安全")
                return
            
            # 检查是否有import socket4.py模块
            if not USE_SOCKET4_FEATURES:
                print("\n错误: 未找到import socket4.py模块，无法进行精密研判")
                return
            
            print("\n【第二阶段：精密研判】")
            
            suspicious_domains_list = [s['domain'] for s in filter_result['suspicious_domains']]
            print(f"对 {len(suspicious_domains_list)} 个可疑域名进行精密研判...")
            
            # 构造DNS记录（对于没有时间戳的，用当前时间）
            import time
            current_time = time.time()
            relevant_records = []
            for domain in suspicious_domains_list:
                relevant_records.append({
                    'domain': domain,
                    'timestamp': current_time,
                    'qtype': 1
                })
            
            # 单个域名详细检测
            print("\n【域名详细检测】")
            print(f"{'域名':<45} {'状态':<10} {'原因'}")
            print("-"*80)
            
            malicious_domains = []
            suspicious_domains = []
            normal_domains = []
            
            # 收集预测统计数据
            pres = []
            ml_true_labels = []
            ml_correct_count = 0
            
            for domain in suspicious_domains_list:
                res = socket4_module.check_dns_record(domain)
                
                # 在线学习：将检测结果添加到学习缓冲区
                if args.online_learn and model is not None:
                    features = extract_domain_features(domain)
                    feature_vector = [features.get(f, 0) for f in FEATURE_NAMES]
                    is_malicious = res["is_malicious"]
                    learning_buffer.add_sample(domain, feature_vector, is_malicious)
                    # 检查是否需要更新模型
                    model, scaler = online_update_model(model, scaler, learning_buffer, args.model)
                
                if res["is_malicious"]:
                    status = "[恶意]"
                    malicious_domains.append(res)
                    final_label = 1
                elif res["is_suspicious"]:
                    status = "[可疑]"
                    suspicious_domains.append(res)
                    final_label = 1
                else:
                    status = "[正常]"
                    normal_domains.append(res)
                    final_label = 0
                
                # 获取真实label
                true_label = domain_labels.get(domain)
                
                # 收集预测数据用于准确度计算
                if res.get('ml_prediction') is not None:
                    pres.append(res['ml_prediction'])
                    ml_true_labels.append(true_label)
                    if true_label is not None and res['ml_prediction'] == true_label:
                        ml_correct_count += 1
                
                print(f"{domain:<45} {status:<10} {res['reason']}")
            
            # 总结报告
            print("\n【检测总结】")
            print(f"总域名数: {filter_result['total_count']}")
            print(f"初步筛选安全: {filter_result['filtered_count']}")
            print(f"精密研判: {len(suspicious_domains_list)}")
            print(f"  - 恶意域名: {len(malicious_domains)}")
            print(f"  - 可疑域名: {len(suspicious_domains)}")
            print(f"  - 正常域名: {len(normal_domains)}")
            
            # 检测率统计
            total = filter_result['total_count']
            if total > 0:
                malicious_rate = len(malicious_domains) / total * 100
                suspicious_rate = len(suspicious_domains) / total * 100
                normal_rate = len(normal_domains) / total * 100
                filtered_rate = filter_result['filtered_count'] / total * 100
                
                print(f"\n【检测率统计】")
                print(f"恶意域名率: {malicious_rate:.2f}%")
                print(f"可疑域名率: {suspicious_rate:.2f}%")
                print(f"正常域名率: {normal_rate:.2f}%")
                print(f"初步筛选率: {filtered_rate:.2f}%")
            
            if malicious_domains:
                print(f"\n发现{len(malicious_domains)}个恶意域名:")
                for item in malicious_domains:
                    print(f"  - {item['domain']}: {item['reason']}")
            
            # 输出研判准确度统计（放在最后）
            if pres:
                labeled_count = sum(1 for l in ml_true_labels if l is not None)
                if labeled_count > 0:
                    ml_accuracy = ml_correct_count / labeled_count * 100
                    print(f"\n研判准确度: {ml_accuracy:.2f}%")
        
        else:
            print("\n请使用 --two-stage 参数进行检测")
    
    if not any([args.judge, args.input, args.generate, args.train, args.inference]):
        pass

if __name__ == '__main__':
    main()
