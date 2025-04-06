from scapy.all import *

from core.trafficWatchfiglet import trafficwatchfiglet
from utils.arg_parser import parse_arguments
from utils.custom_logger import setup_logging
from utils.protocol_map import protocol_handlers

setup_logging()


def analyze_packets(packets, protocol_filter=None, packet_count=None):
    """
   分析一组数据包，基于指定的协议过滤器和数据包数量进行操作。 对于每个数据包，如果指定了协议过滤器，则调用相应的协议处理程序。 如果未指定过滤器，则可以使用默认处理程序处理数据包或跳过该数据包。

   参数说明：

   packets：需要分析的数据包集合。

   protocol_filter：（可选）指定用于过滤数据包的协议。

   packet_count：（可选）要分析的数据包数量。
    """
    logging.info(f"{trafficwatchfiglet()}")
    logging.info("----------------------------------------")

    displayed_count = 0

    for packet in packets:
        if packet_count is not None and displayed_count >= packet_count:
            break

        # If a protocol filter is specified, use the corresponding handler
        if protocol_filter:
            if handler := protocol_handlers.get(protocol_filter):
                handler(packet)
                displayed_count += 1
                continue

        # 如果没有指定过滤器，或者协议不被支持，
        # 你可以选择打印每个数据包的基本信息，或者跳过它。
        # 例如，你可能想实现一个类似于 print_basic_packet_info(packet) 的函数
        # print_basic_packet_info(packet) # 一个展示数据包基本信息的假想函数

        displayed_count += 1


def main():
    args = parse_arguments()

    pcap_file = args.file

    if not os.path.exists(pcap_file):
        logging.error(f"The file {pcap_file} does not exist.")
        exit(1)

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        logging.error(f"Error reading {pcap_file}: {e}")
        exit(1)

    analyze_packets(packets, args.protocol, args.count)

    if output := args.write:
        if ".pcap" not in output:
            output = f"{output}.pcap"

        filtered_packets = packets[:args.count] if args.count is not None else packets
        try:
            wrpcap(output, filtered_packets)
            logging.info(f"Saved in {output}")
        except Exception as e:
            logging.error(f"Error writing to {output}: {e}")
            exit(1)


if __name__ == '__main__':
    main()
