from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
from scapy.layers.snmp import SNMP
from scapy.packet import Raw

from utils.packet_utils import print_packet_details


def handle_arp(packet):
    """
    处理并记录ARP数据包的详细信息。
    参数：

    packet：待处理的数据包，预期为ARP数据包
    """
    if not packet.haslayer(ARP):
        return
    details = {
        "Operation": "Request" if packet[ARP].op == 1 else "Reply",
        "Source IP": packet[ARP].psrc,
        "Destination IP": packet[ARP].pdst,
        "Source MAC": packet[ARP].hwsrc,
        "Destination MAC": packet[ARP].hwdst
    }
    print_packet_details("ARP", details)


def handle_icmp(packet):
    """
    处理并记录ICMP数据包的详细信息。

    参数：

    packet：待处理的数据包，预期为ICMP数据包。
    """
    if not packet.haslayer(ICMP):
        return
    details = {
        "Type": packet[ICMP].type,
        "Code": packet[ICMP].code
    }
    print_packet_details("ICMP", details)


def handle_tcp(packet):
    """
    处理并记录TCP数据包的详细信息，包括源端口、目标端口和标志位。

    参数：

    packet：待处理的数据包，预期为TCP数据包。
    """
    if not packet.haslayer(TCP):
        return
    details = {
        "Source Port": packet[TCP].sport,
        "Destination Port": packet[TCP].dport,
        "Flags": packet[TCP].flags
    }
    print_packet_details("TCP", details)


def handle_udp(packet):
    """
    处理并记录UDP数据包的详细信息，包括源端口和目标端口。

    参数：

    packet：待处理的数据包，预期为UDP数据包。
    """
    if not packet.haslayer(UDP):
        return
    details = {
        "Source Port": packet[UDP].sport,
        "Destination Port": packet[UDP].dport
    }
    print_packet_details("UDP", details)


def handle_dns(packet):
    """
    处理并记录DNS数据包的详细信息，区分DNS查询和响应。

    参数：

    packet：待处理的数据包，预期为DNS数据包。
    """
    if packet.haslayer(DNSQR):
        details = {"Query Name": packet[DNSQR].qname.decode('utf-8')}
        print_packet_details("DNS Request", details)
    elif packet.haslayer(DNSRR):
        details = {"Response Name": packet[DNSRR].rrname.decode('utf-8')}
        print_packet_details("DNS Response", details)


def handle_dhcp(packet):
    """
    处理并记录DHCP数据包的详细信息，包括DHCP选项。

参数：

packet：待处理的数据包，预期为DHCP数据包。
    """
    if not packet.haslayer(DHCP):
        return
    details = {option[0]: option[1] for option in packet[DHCP].options if isinstance(option, tuple)}
    print_packet_details("DHCP", details)


def handle_http(packet):
    """
    处理并记录HTTP数据包的详细信息，特别关注其有效负载（payload）。

参数：

packet：待处理的数据包，预期包含HTTP数据。
    """
    if packet.haslayer(Raw):
        details = {"Payload": packet[Raw].load.decode(errors='replace')}
        print_packet_details("HTTP", details)


def handle_snmp(packet):
    """
    处理并记录SNMP数据包的详细信息，包括版本和社区字符串（community string）。

参数：

packet：待处理的数据包，预期为SNMP数据包。
    """
    if not packet.haslayer(SNMP):
        return
    details = {
        "Version": packet[SNMP].version,
        "Community": packet[SNMP].community.decode('utf-8')
    }
    print_packet_details("SNMP", details)


def handle_llmnr(packet):
    """
    处理并记录LLMNR数据包的详细信息，区分查询和响应。

参数：

packet：待处理的数据包，预期为LLMNR数据包
    """
    if packet.haslayer(LLMNRQuery):
        details = {"Query Name": packet[LLMNRQuery].qname.decode('utf-8')}
        print_packet_details("LLMNR Query", details)
    elif packet.haslayer(LLMNRResponse):
        details = {"Response Name": packet[LLMNRResponse].rrname.decode('utf-8')}
        print_packet_details("LLMNR Response", details)


def handle_netbios(packet):
    """
    处理并记录NetBIOS数据包的详细信息，区分查询请求和响应。

参数：

packet：待处理的数据包，预期为NetBIOS数据包。
    """
    if packet.haslayer(NBNSQueryRequest):
        details = {"NetBIOS Name": packet[NBNSQueryRequest].QUESTION_NAME}
        print_packet_details("NetBIOS Query Request", details)
    elif packet.haslayer(NBNSQueryResponse):
        details = {"NetBIOS Name": packet[NBNSQueryResponse].RR_NAME}
        print_packet_details("NetBIOS Query Response", details)
