from scapy.all import *
from scapy.all import rdpcap, IP, UDP, DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from collections import defaultdict
from rich import print
import csv
import sys
import xxhash
import dns.rdata
import socket
from scapy.all import rdpcap, DNSRR

burst_filter=defaultdict(list)
cold_filter=defaultdict(list)
BUKET_SIZE = 100
def default0():
    return 0
burst_filter_info=defaultdict(default0) #记录每个桶曾经存储过的最大数据量

def decode_txt_rdata(rdata_bytes):
    """手动解码 TXT 的 rdata（标准格式：长度+文本，可多段）"""
    result = []
    i = 0
    while i < len(rdata_bytes):
        length = rdata_bytes[i]
        i += 1
        result.append(rdata_bytes[i:i+length].decode())
        i += length
    return ' '.join(result)
def extract_rdata_payload(rr):
    """
    从 DNS 资源记录（RR）中提取可读的载荷内容。
    参数 rr: Scapy 的 DNSRR 对象
    """
    rdata = rr.rdata  # 保持原始类型（可能是 bytes 或 str）

    # A 记录
    if rr.type == 1:
        if isinstance(rdata, bytes) and len(rdata) == 4:
            return socket.inet_ntoa(rdata)
        else:
            return str(rdata)  # 已经是字符串 IP 或其它

    # AAAA 记录
    elif rr.type == 28:
        if isinstance(rdata, bytes) and len(rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, rdata)
        else:
            return str(rdata)

    # NS, CNAME, PTR (域名)
    elif rr.type in (2, 5, 12):
        if isinstance(rdata, bytes):
            return rdata.decode()
        else:
            return str(rdata)

    # MX 记录
    elif rr.type == 15:
        if isinstance(rdata, bytes):
            priority = int.from_bytes(rdata[:2], byteorder='big')
            domain = rdata[2:].decode()
            return f"{priority} {domain}"
        else:
            return str(rdata)

    # TXT 记录
    elif rr.type == 16:
        if hasattr(rr, 'strings'):
            parts = [s.decode() if isinstance(s, bytes) else str(s) for s in rr.strings]
            return ' '.join(parts)
        else:
            if isinstance(rdata, bytes):
                return decode_txt_rdata(rdata)
            else:
                return str(rdata)

    # SOA 记录（简化处理）
    elif rr.type == 6:
        if isinstance(rdata, bytes):
            return rdata.hex()
        else:
            return str(rdata)

    # 其他未知类型
    else:
        if isinstance(rdata, bytes):
            return rdata.hex()
        else:
            return str(rdata)
# def parse_dns_rdata_with_dnspython(scapy_dnsrr):
#     """
#     使用 dnspython 将 Scapy DNSRR 对象中的 rdata 解析为结构化数据。
#     """
#     try:
#         # 1. 获取 Scapy 包中的原始数据
#         record_type = scapy_dnsrr.type  # DNS 记录类型（整数，如 1 表示 A，5 表示 CNAME）
#         record_class = scapy_dnsrr.rclass  # DNS 记录类（整数，通常是 1 表示 IN）
#         ttl = scapy_dnsrr.ttl  # TTL 值
#         raw_rdata = bytes(scapy_dnsrr.rdata)  # 将 rdata 转换为原始字节流

#         # 2. 使用 dnspython 解析
#         # 注意：dnspython 的 from_wire 需要完整的 DNS 消息，这里只处理 rdata 部分，
#         # 所以需要手动构建一个简单的消息上下文。对于常见类型，这种方式有效。
#         # 一个更通用但略复杂的方法涉及 dns.message.from_wire，但上述方法对多数场景足够。
#         rdata_obj = dns.rdata.from_wire(
#             record_class,           # 这里直接使用整数
#             record_type,
#             raw_rdata,
#             0,                      # 起始偏移
#             len(raw_rdata)        # 数据长度
#         )
#         return rdata_obj,ttl


#     except Exception as e:
#         print(f"解析 rdata 失败 (Type: {record_type}): {e}")
#         return None, None
    
# def get_rdata_value(rdata_obj, record_type=None):
#     """
#     从 dnspython 解析出的 rdata 对象中提取主要载荷值（字符串形式）。
    
#     参数:
#         rdata_obj: dnspython 解析后的对象（如 dns.rdtypes.IN.A.A）。
#         record_type: 可选，DNS 记录类型整数。如果提供，将用于特殊处理；
#                      如果不提供，将尝试从 rdata_obj 的 rdtype 属性获取。
    
#     返回:
#         字符串，表示该记录的核心内容（例如 IP 地址、域名、TXT 文本等）。
#         如果无法提取，返回 str(rdata_obj) 或空字符串。
#     """
#     if rdata_obj is None:
#         return ""

#     # 如果没有显式提供 record_type，尝试从对象中获取
#     if record_type is None:
#         if hasattr(rdata_obj, 'rdtype'):
#             record_type = rdata_obj.rdtype
#         else:
#             # 实在无法获取，直接返回字符串形式
#             return str(rdata_obj)

#     # 根据类型提取最常用的属性
#     if record_type == dns.rdatatype.A:          # 1
#         return getattr(rdata_obj, 'address', '')
#     elif record_type == dns.rdatatype.AAAA:     # 28
#         return getattr(rdata_obj, 'address', '')
#     elif record_type == dns.rdatatype.CNAME:    # 5
#         return str(getattr(rdata_obj, 'target', ''))
#     elif record_type == dns.rdatatype.NS:       # 2
#         return str(getattr(rdata_obj, 'target', ''))
#     elif record_type == dns.rdatatype.PTR:      # 12
#         return str(getattr(rdata_obj, 'target', ''))
#     elif record_type == dns.rdatatype.MX:       # 15
#         exchange = getattr(rdata_obj, 'exchange', None)
#         pref = getattr(rdata_obj, 'preference', None)
#         if exchange:
#             return f"{pref} {exchange}" if pref is not None else str(exchange)
#         return ''
#     elif record_type == dns.rdatatype.TXT:      # 16
#         strings = getattr(rdata_obj, 'strings', ())
#         # 将多个字符串连接成一个字符串（通常 TXT 可能包含多个片段）
#         return ''.join(s.decode() if isinstance(s, bytes) else str(s) for s in strings)
#     elif record_type == dns.rdatatype.SOA:      # 6
#         mname = getattr(rdata_obj, 'mname', '')
#         rname = getattr(rdata_obj, 'rname', '')
#         serial = getattr(rdata_obj, 'serial', '')
#         return f"{mname} {rname} {serial}"
#     elif record_type == dns.rdatatype.SRV:      # 33
#         target = getattr(rdata_obj, 'target', '')
#         port = getattr(rdata_obj, 'port', '')
#         priority = getattr(rdata_obj, 'priority', '')
#         weight = getattr(rdata_obj, 'weight', '')
#         return f"{priority} {weight} {port} {target}"
#     else:
#         # 未知类型：返回字符串表示
#         return str(rdata_obj)
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
        if IP in p and UDP in p and DNS in p and p[DNS].an:  # 确保存在问题段
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
        # 2. 提取 有效载荷 与 DNS缓存中的 TTL
        dns_layer = pkt[DNS]
        ttl = None
        rdata_value = None
        if dns_layer.an:                     # 存在 Answer 记录
            ans = dns_layer.an[0] if isinstance(dns_layer.an, list) else dns_layer.an#提取answer记录
            if hasattr(ans, 'ttl'):
                ttl = ans.ttl
            # 提取载荷
            rdata_value = extract_rdata_payload(ans)
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
            'RData': rdata_value,
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
        print(f"{'Timestamp':<20} {'Client_IP':<16} {'TTL':<5} {'Payload_Size':<10} {'Domain':<35} {'Record_Type'}{'RData'}")
        print("-" * 95)
        for row in results:
            domain_str = str(row['Domain'])[:35] if row['Domain'] else 'None'
            print(f"{row['Timestamp']:<20.6f} {row['Client_IP']:<16} {row['TTL']:<5} {row['Payload_Size']:<10} {domain_str:<35} {row['Record_Type']}{row['RData']}")

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
    k = h%BUKET_SIZE #将哈希值取余得到过滤器引索
    c = burst_filter_info #计数列表别名

    if not l[k]:#如果热过滤器中不存在该哈希值，则将dnsinfo添加到对应的列表中
        l[k].append(dnsinfo)
        c[k] += 1
    else:#如果热过滤器中存在该哈希值
        size = len(l[k]) #读取已有数据的个数
        if registered_domain == extract_registered_domain(l[k][0]['Domain']):#如果热过滤器中存在该哈希值,且该哈希值对应的注册域与当前dnsinfo的注册域相同，并且桶尚未到达上限，则将dnsinfo添加到对应的列表中
            if size <= BUKET_SIZE:
                l[k].append(dnsinfo)
                c[k] += 1
            else:
                pass
        else:#如果热过滤器中存在该哈希值，但二级域名不同，那么通过概率来决定保留哪个，另一个则移交给冷过滤器 
            if h%c[k] == 0:#1/c[k]的概率成功,将已有的列表交给冷过滤器，用新数据将其覆盖
                add_cold_item(l[k])
                l[k].clear
                l[k].append(dnsinfo)
                c[k] += 1
            else:#size-1/size的概率失败,将新数据交给冷过滤器
                add_cold_item([dnsinfo])
    

def add_cold_item(dnsinfos):
    '''
    将热过滤器中被淘汰的数据放入冷过滤器中。
    参数：
        dnsinfos(list):被淘汰的数据，是一个列表
    '''

    list = dnsinfos.copy()#复制被淘汰的数据
    dnsinfo = list[0]
    registered_domain=extract_registered_domain(dnsinfo['Domain'])#提取注册域
    h = xxhash32(registered_domain)#根据域名提取注册域并计算哈希值
    l = cold_filter#冷过滤器别名

    l[registered_domain].extend(list)#将被淘汰的数据添加到冷过滤器中
    
    

if __name__ == "__main__":
    # 替换为实际 PCAP 文件路径
    pcap_file = "filtering/noise.pcapng"
    valid_packets = filter_dns_packets(pcap_file)
    print(f"过滤后得到 {len(valid_packets)} 个有效 DNS 数据包")
    dns_infos = extract_dns_info(valid_packets)
    for dns_info in dns_infos:
        add_hot_item(dns_info)
        # print(burst_filter)
        # print(cold_filter)
    print(burst_filter)
    print(cold_filter)
