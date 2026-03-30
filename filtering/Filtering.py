from scapy.all import *
from scapy.all import rdpcap, IP, UDP, DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
import csv
import sys

pcap_interact = rdpcap("interact.pcap")
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

        results.append({
            'Timestamp': timestamp,
            'TTL': ttl,
            'Payload_Size': payload_size,
            'Domain': domain,
            'Record_Type': record_type
        })

    # 输出结果
    if output_csv:
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['Timestamp', 'TTL', 'Payload_Size', 'Domain', 'Record_Type'])
            writer.writeheader()
            writer.writerows(results)
        print(f"[✓] 已保存 {len(results)} 条记录到 {output_csv}")
    else:
        # 控制台打印表格
        print(f"{'Timestamp':<20} {'TTL':<5} {'Payload_Size':<10} {'Domain':<35} {'Record_Type'}")
        print("-" * 80)
        for row in results:
            print(f"{row['Timestamp']:<20.6f} {row['TTL']:<5} {row['Payload_Size']:<10} {str(row['Domain'])[:35]:<35} {row['Record_Type']}")

    return results

if __name__ == "__main__":
    # 替换为实际 PCAP 文件路径
    pcap_file = "interact.pcap"
    valid_packets = filter_dns_packets(pcap_file)
    print(f"过滤后得到 {len(valid_packets)} 个有效 DNS 数据包")
    extract_dns_info(valid_packets)