from scapy.all import *
from scapy.all import rdpcap, IP, UDP, DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from collections import defaultdict
import csv
import sys
import xxhash

burst_filter=defaultdict(list)
cold_filter=defaultdict(list)

def filter_dns_packets(pcap_path):
    """
    从 PCAP 文件中过滤出满足以下条件的 DNS 数据包：
    - 包含 IP、UDP 和 DNS 层
    - DNS 层具有有效的 QR 标志（0 或 1，这里仅要求存在）
    - qdcount == 1（只有一个 DNS 问题）
    - qname 字段存在且可解码为字符串

    参数:
        pcap_path (str): PCAP 文件路径

    返回:
        list: 满足条件的 scapy 数据包对象列表
    """
    filtered_packets = []
    
    # 读取 PCAP 文件（注意：对于大文件建议使用 PcapReader 迭代）
    packets = rdpcap(pcap_path)
    
    for p in packets:
        # 检查是否包含 IP、UDP 和 DNS 层
        if IP in p and UDP in p and DNS in p:
            dns_layer = p[DNS]
            
            # 检查 QR 标志有效（DNS 标准中 QR 为 0 或 1，此处仅需字段存在）
            # 同时确保 qdcount == 1
            if hasattr(dns_layer, 'qr') and dns_layer.qdcount == 1:
                # 获取 DNS 问题部分（第一个问题）
                if dns_layer.qd:
                    qname = dns_layer.qd.qname
                    # 尝试解码 qname（通常为字节串，如 b'example.com.'）
                    try:
                        # DNS 域名使用类似 'www.example.com.' 的格式，解码为 ASCII/UTF-8
                        decoded_qname = qname.decode('utf-8')
                        # 如果解码成功且非空，则认为可解码
                        if decoded_qname:
                            filtered_packets.append(p)
                    except (UnicodeDecodeError, AttributeError):
                        # 解码失败，跳过该数据包
                        continue
                # 如果没有 qd 字段，也跳过
                else:
                    continue
            else:
                continue
        else:
            continue
    
    return filtered_packets

def safe_get_udp_payload_size(pkt):
    """安全获取 UDP 负载的字节长度"""
    try:
        # 方法1：获取 UDP 层的 payload（下一层或 Raw 数据）
        if UDP in pkt:
            udp_layer = pkt[UDP]
            # payload 可能是 Packet 或 bytes
            if hasattr(udp_layer, 'payload') and udp_layer.payload:
                return len(bytes(udp_layer.payload))
            # 备选：直接读取 load 字段
            elif hasattr(udp_layer, 'load') and udp_layer.load:
                return len(udp_layer.load)
        return 0
    except Exception:
        return 0
    
def extract_registered_domain(domain):
    """
    从完整域名中提取“二级域名.顶级域”
    示例：www.example.com -> example.com
          mail.example.co.uk -> example.co.uk  (注意：此处会误判，应为 example.co.uk 但简单方法只取最后两级)
    """
    if not domain:
        return None
    # 去除末尾可能存在的点
    domain = domain.rstrip('.')
    parts = domain.split('.')
    if len(parts) < 2:
        return domain  # 无法提取，返回原值
    # 取最后两部分
    return '.'.join(parts[-2:])
def extract_dns_info(packets, output_csv=None):
    """
    从 pcap 文件中提取 DNS 查询/响应的关键信息。

    参数:
        packets: 输入的packets
        output_csv (str, optional): 输出的 CSV 文件路径。不提供则打印到控制台。

    返回:
        list: 包含字典或元组的列表，每个元素代表一个 DNS 包的信息。
    """
    results = []

    for pkt in packets:
        # 检查是否同时包含 IP、UDP 和 DNS 层
        if IP not in pkt or UDP not in pkt or DNS not in pkt:
            continue

        # 1. 时间戳 (秒，从 epoch 开始)
        timestamp = pkt.time

        # 2. IP 层的 TTL
        ttl = pkt[IP].ttl

        # 3. 有效载荷大小：UDP 负载的长度（即 DNS 消息长度）
        payload_size = safe_get_udp_payload_size(pkt)

        # 4. 域名和记录类型：从 DNS 查询段（Question Section）提取
        dns_layer = pkt[DNS]
        if dns_layer.qd:                     # 存在问题段
            # qd 可能是一个列表，通常只有一个元素
            question = dns_layer.qd[0] if isinstance(dns_layer.qd, list) else dns_layer.qd
            # 域名可能是 bytes 类型，需要解码为字符串
            domain = question.qname.decode() if isinstance(question.qname, bytes) else str(question.qname)
            record_type = question.qtype      # 数字格式，如 1=A, 28=AAAA
        else:
            domain = None
            record_type = None

        #5. 主机端ip
        client_ip = pkt[IP].src

        results.append({
            'Timestamp': timestamp,
            'TTL': ttl,
            'Payload_Size': payload_size,
            'Domain': domain,
            'Record_Type': record_type,
            'Client_IP': client_ip,
        })

    # 输出结果
    if output_csv:
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['Timestamp', 'TTL', 'Payload_Size', 'Domain', 'Record_Type'])
            writer.writeheader()
            writer.writerows(results)
        print(f"[✓] 已保存 {len(results)} 条记录到 {output_csv}")
    else:
        # 打印到控制台，调整列宽
        print(f"{'Timestamp':<20} {'Client_IP':<16} {'TTL':<5} {'Payload_Size':<10} {'Domain':<35} {'Record_Type'}")
        print("-" * 95)
        for row in results:
            domain_str = str(row['Domain'])[:35] if row['Domain'] else 'None'
            print(f"{row['Timestamp']:<20.6f} {row['Client_IP']:<16} {row['TTL']:<5} {row['Payload_Size']:<10} {domain_str:<35} {row['Record_Type']}")

    return results

def xxhash32(seed_str: str) -> int:
    return xxhash.xxh32(seed_str.encode()).intdigest()
def add_hot_item(dnsinfo):
    '''
    将提取好的dns关键信息放入热过滤器中。

    参数：
        dnsinfo(list):函数extract_dns_info输出的列表的单元
    '''
    registered_domain=extract_registered_domain(dnsinfo['Domain'])#提取注册域
    h = xxhash32(registered_domain)#根据域名提取注册域并计算哈希值
    l = burst_filter#突发过滤器别名
    k = h%100 #将哈希值取余得到过滤器引索

    if not l[k]:#如果热过滤器中不存在该哈希值，则将dnsinfo添加到对应的列表中
        l[k].append(dnsinfo)
    elif registered_domain == extract_registered_domain(l[k][0]['Domain']):#如果热过滤器中存在该哈希值,且该哈希值对应的注册域与当前dnsinfo的注册域相同，则将dnsinfo添加到对应的列表中
        l[k].append(dnsinfo)
    else:#如果热过滤器中存在该哈希值，但二级域名不同，那么通过概率来决定保留哪个，另一个则移交给冷过滤器
        size = len(l[k]) #读取已有数据的个数
        if h%size == 0:#1/size的概率成功,将已有的列表交给冷过滤器，用新数据将其覆盖
            add_cold_item(l[k])
            l[k].clear
            l[k].append(dnsinfo)
    
    print(f"第{k}现在有{len(l[k])}个数据")

def add_cold_item(dnsinfo):
    pass

    
    

if __name__ == "__main__":
    # 替换为实际 PCAP 文件路径
    pcap_file = "filtering/noise.pcapng"
    valid_packets = filter_dns_packets(pcap_file)
    print(f"过滤后得到 {len(valid_packets)} 个有效 DNS 数据包")
    dns_infos = extract_dns_info(valid_packets)
    for dns_info in dns_infos:
        add_hot_item(dns_info)
