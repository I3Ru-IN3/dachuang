from scapy.all import *
from scapy.all import rdpcap, IP, UDP, DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR

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

if __name__ == "__main__":
    # 替换为实际 PCAP 文件路径
    pcap_file = "cobalt_strike_1.pcapng"
    valid_packets = filter_dns_packets(pcap_file)
    print(f"过滤后得到 {len(valid_packets)} 个有效 DNS 数据包")
    for p in valid_packets:
        print(p)