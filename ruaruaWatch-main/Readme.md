ruaruaWatch
ruaruaWatch 是一个数据包嗅探工具，允许您从 PCAP 文件中监控和分析网络流量。它提供对多种网络协议的深入了解，可帮助进行网络故障排查、安全分析等。

特性
针对 ARP、ICMP、TCP、UDP、DNS、DHCP、HTTP、SNMP、LLMNR 和 NetBIOS 协议的特定数据包分析。

基于协议、源 IP、目标 IP、源端口、目标端口等条件的数据包过滤。

捕获数据包的摘要统计信息。

支持交互模式以深入检查数据包。

为每个捕获的数据包添加时间戳。

用户友好的彩色输出，提升可读性。

要求
Python 3.x

scapy

argparse

pyshark

colorama


用法

python3 ruaruawatch.py --help                                    
usage: ruaruawatch.py [-h] -f FILE [-p {ARP,ICMP,TCP,UDP,DNS,DHCP,HTTP,SNMP,LLMNR,NetBIOS}] [-c COUNT] [-w WRITE]

数据包嗅探工具

选项：
-h, --help            显示此帮助信息并退出
-f FILE, --file FILE  要分析的 .pcap 文件路径
-p {ARP,ICMP,TCP,UDP,DNS,DHCP,HTTP,SNMP,LLMNR,NetBIOS}, --protocol {ARP,ICMP,TCP,UDP,DNS,DHCP,HTTP,SNMP,LLMNR,NetBIOS}
                     按特定协议过滤
-c COUNT, --count COUNT
                     要显示的数据包数量
-w WRITE, --write WRITE
                     要写入的 .pcap 文件路径


要从 PCAP 文件中分析数据包，请使用以下命令
python ruaruawatch.py -f path/to/your.pcap

要指定协议过滤器（例如 HTTP）并限制显示的数据包数量（例如 10），请使用：
python ruaruawatch.py -f path/to/your.pcap -p HTTP -c 10


选项
-f 或 --file：用于分析的 PCAP 文件路径。

-p 或 --protocol：按协议过滤数据包（ARP、ICMP、TCP、UDP、DNS、DHCP、HTTP、SNMP、LLMNR、NetBIOS）。

-c 或 --count：限制显示的数据包数量。

-w 或 --write：要写入的 .pcap 文件路径。