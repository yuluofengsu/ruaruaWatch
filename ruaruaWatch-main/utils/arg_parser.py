import argparse


def parse_arguments():
    """
    解析数据包嗅探工具的命令行参数。 返回值: argparse.Namespace：一个包含解析后参数的对象。
    """
    parser = argparse.ArgumentParser(description='Packet Sniffer Tool')
    parser.add_argument('-f', '--file', required=True, help='Path to the .pcap file to analyze')
    parser.add_argument('-p', '--protocol',
                        choices=['ARP', 'ICMP', 'TCP', 'UDP', 'DNS', 'DHCP', 'HTTP', 'SNMP', 'LLMNR', 'NetBIOS'],
                        help='Filter by specific protocol')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to display')
    parser.add_argument('-w', '--write', help='Path to the .pcap file to write')

    return parser.parse_args()
