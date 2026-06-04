from scapy.all import rdpcap, IP, UDP, DNS, DNSQR, sniff ,show_interfaces,IFACES
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from itertools import groupby
from collections import defaultdict
from rich import print
from config_loader import config

import csv
import sys
import xxhash
import dns.rdata
import socket
import logging
import time
import threading


config.load("filtering/config.yaml")  # 加载配置文件
burst_filter=defaultdict(list)
cold_filter=defaultdict(list)
BUKET_SIZE = 100
burst_filter_info=defaultdict(lambda :0) #记录每个桶曾经存储过的最大数据量

class PacketGrouper:
    """将原始包聚合成 group，按条件触发处理"""
    def __init__(self, group_size=50, timeout=1.0, callback=None):
        self.group = []
        self.group_size = group_size
        self.timeout = timeout
        self.callback = callback      # 当 group 准备好时调用的函数
        self.buffer = []
        self.last_flush = time.time()
        self.lock = threading.Lock()

    def add(self, packet):
        with self.lock:
            if not filter_dns_packets([packet]):#如果数据包不满足过滤条件
                return
            self.buffer.append(packet)
            if len(self.buffer) >= self.group_size:
                self._flush()
            else:
                # 检查超时（可以在独立线程中定期检查，这里简化）
                pass

    def _flush(self):
        if not self.buffer:#如果缓冲区为空，则不进行处理
            return
        #如果缓冲区不为空，将buffer传入group，并清空buffer重置计时

        self.group = extract_dns_info(self.buffer)#提取数据包中的dns信息
        self.buffer.clear()
        self.last_flush = time.time()

        if self.callback:
            self.callback(self.group)

    def start_timeout_checker(self):
        """启动一个线程定期检查超时"""
        def check():
            while True:
                time.sleep(self.timeout)
                #每隔timeout秒检查一次，若满足条件则启用flush函数
                with self.lock:
                    if self.buffer and (time.time() - self.last_flush) >= self.timeout:
                        self._flush()
        thread = threading.Thread(target=check, daemon=True)
        thread.start()

def setup_logging():
    log_enabled = config.get('logging.enabled', True)

    if not log_enabled:
        logging.disable(logging.CRITICAL)  # 禁止所有日志输出
        return
    
    log_level = config.get('logging.level', 'INFO')
    logging.basicConfig(level=getattr(logging,log_level), format='%(asctime)s - %(levelname)s - %(message)s')
setup_logging()  # 初始化日志系统

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

def filter_dns_packets(pcap_path_or_packets):
    """
    从 PCAP 文件中过滤出满足以下条件的 DNS 数据包：
    - 包含 IP、UDP 和 DNS 层
    - DNS 层具有有效的 QR 标志（0 或 1，这里仅要求存在）
    - qdcount == 1（只有一个 DNS 问题）
    - qname 字段存在且可解码为字符串

    参数:
        pcap_path_or_packets: PCAP 文件路径或packets列表

    返回:
        list: 满足条件的 scapy 数据包对象列表
    """
    filtered_packets = []
    
    # 读取 PCAP 文件（注意：对于大文件建议使用 PcapReader 迭代）
    if isinstance(pcap_path_or_packets, str):
        packets = rdpcap(pcap_path_or_packets)
    elif isinstance(pcap_path_or_packets, list):
        packets = pcap_path_or_packets
    
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
                    logging.debug("数据包的 DNS 层缺少问题段，已跳过")
                    continue
            else:
                logging.debug("数据包的 DNS 层缺少有效的 QR 标志或 qdcount 不为 1，已跳过")
                continue
        else:
            logging.debug("数据包不含有 IP、UDP 和 DNS 层，或 DNS 层缺少问题段，已跳过")
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
            registered_domain = extract_registered_domain(domain)  # 提取注册域
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
            'Registered_Domain': registered_domain,
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
        # print(f"{'Timestamp':<20} {'Client_IP':<16} {'TTL':<5} {'Payload_Size':<10} {'Domain':<35} {'Record_Type'}{'RData'}")
        # print("-" * 95)
        # for row in results:
        #     domain_str = str(row['Domain'])[:35] if row['Domain'] else 'None'
        #     print(f"{row['Timestamp']:<20.6f} {row['Client_IP']:<16} {row['TTL']:<5} {row['Payload_Size']:<10} {domain_str:<35} {row['Record_Type']}{row['RData']}")
        pass

    return results

def xxhash32(seed_str: str) -> int:
    return xxhash.xxh32(seed_str.encode()).intdigest()
def add_hot_item(registered_domain,dnsinfos):
    '''
    将提取好的dns关键信息放入热过滤器中。

    参数：
        registered_domain(str):从域名中提取的注册域
        dnsinfos(list):dnsinfo的列表，包含了同一注册域的多个dns信息
    '''
    h = xxhash32(registered_domain)#根据域名提取注册域并计算哈希值
    l = burst_filter#突发过滤器别名
    k = h%BUKET_SIZE #将哈希值取余得到过滤器引索
    c = burst_filter_info #计数列表别名
    size_of_dnsinfos = len(dnsinfos) #当前dnsinfo的个数

    if not l[k]:#如果热过滤器中不存在该哈希值，则将dnsinfo添加到对应的列表中
        l[k].extend(dnsinfos)#将dnsinfos添加到热过滤器中
        c[k] += size_of_dnsinfos#更新该哈希值对应的计数器，记录当前桶中数据的个数
        return
    
    size = len(l[k]) #读取已有数据的个数
    if registered_domain == extract_registered_domain(l[k][0]['Registered_Domain']):#如果热过滤器中存在该哈希值,且该哈希值对应的注册域与当前dnsinfo的注册域相同，并且桶尚未到达上限，则将dnsinfo添加到对应的列表中
        if size <= BUKET_SIZE:
            l[k].extend(dnsinfos)
            c[k] += size_of_dnsinfos
        else:
            pass
    else:#如果热过滤器中存在该哈希值，但二级域名不同，那么通过概率来决定保留哪个，另一个则移交给冷过滤器 
        if h%c[k] == 0:#1/c[k]的概率成功,将已有的列表交给冷过滤器，用新数据将其覆盖
            add_cold_item(l[k])
            l[k].clear
            l[k].extend(dnsinfos)
            c[k] += size_of_dnsinfos
        else:#size-1/size的概率失败,将新数据交给冷过滤器
            add_cold_item(dnsinfos)
    

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
    
    
def add_group_to_filters(group):
    '''
    将dnsinfo列表通过group分组后添加到过滤器中。
    参数：
        group(list):dnsinfo列表
    '''
    group.sort(key=lambda x: x['Registered_Domain'])#对每组数据按照域名进行排序，保证同一注册域的数据在一起
    for registered_domain,dns_info_group in groupby(group, key=lambda x: x['Registered_Domain']):
        add_hot_item(registered_domain,list(dns_info_group))#注册域与dns信息组传入add_hot_item函数进行过滤器更新


def add_packet_to_group(packet,group):
    '''
    将数据包提取出的dnsinfo添加到group中。
    参数：
        packet:数据包
    '''

    if not filter_dns_packets([packet]):#如果数据包不满足过滤条件
        #logging.debug("数据包不满足过滤条件，已跳过")#打印提示信息
        return

    dnsinfos = extract_dns_info([packet])#提取数据包中的dns信息

    group.extend(dnsinfos)#以（注册域，dnsinfo）的形式将数据添加到group中
    if len(group) == 1000:#每1000条数据为一组，进行一次过滤器的更新
        add_group_to_filters(group)#将group列表添加到过滤器中
        group.clear()#清空group，为下一组数据做准备
        return



def main():
    capture_cfg = config._config.get('capture', {})
    ifacd_index = capture_cfg.get('interface_index', None)
    try:
        iface = IFACES.dev_from_index(ifacd_index)
    except Exception as e:
        logging.error(f"无法找到指定的网络接口索引 {ifacd_index}: {e}")
        return


    timeout = capture_cfg.get('timeout', 0)
    pcap_file = capture_cfg.get('pcap_file', None)
    offline_mode = capture_cfg.get('offline_mode', False)
    logging.info(f"开始抓包，接口: {iface}, 超时: {timeout}s")




    # valid_packets = filter_dns_packets(pcap_file)#过滤出有效的DNS数据包
    # print(f"过滤后得到 {len(valid_packets)} 个有效 DNS 数据包")
    # dns_infos = extract_dns_info(valid_packets)#筛选出dns数据信息


    group = []
    grouper = PacketGrouper(group_size=1000, timeout=1, callback=add_group_to_filters)
    grouper.start_timeout_checker()  # 启动超时检查线程

    if offline_mode:
        sniff(prn=lambda pkt: grouper.add(pkt), store=0,timeout = timeout,offline=pcap_file)#将数据包逐个传入add_packet_to_group函数进行过滤器更新
    else:
        sniff(prn=lambda pkt: grouper.add(pkt), store=0,timeout = timeout,iface=IFACES.dev_from_index(19))#将数据包逐个传入add_packet_to_group函数进行过滤器更新
    
    if group:#处理最后一组数据
        add_group_to_filters(group)#将group列表添加到过滤器中
        group.clear()#清空group

    # print(burst_filter)
    # print(cold_filter)
    print(burst_filter)
    print(cold_filter)

if __name__ == "__main__":
    main()

