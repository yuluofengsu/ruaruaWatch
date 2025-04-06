import logging


def print_packet_details(packet_type, details):
    """
    使用预定义的日志格式记录数据包的详细信息。

参数：

packet_type：表示数据包类型的字符串（例如：'ARP'，'TCP'）。

details：包含数据包详细信息的键值对字典。
    """
    logging.info(f"{packet_type} Packet Detected")
    for key, value in details.items():
        logging.info(f"{key:18}: {value}")
