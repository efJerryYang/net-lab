#ifndef CONFIG_H
#define CONFIG_H

#define ETHERNET
#define ARP
#define IP
#define ICMP
#define UDP
#define TCP
#define HTTP

#ifdef TEST
#define NET_IF_IP          \
    {                      \
        192, 168, 163, 103 \
    } // 测试用网卡ip地址
#define NET_IF_MAC                         \
    {                                      \
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66 \
    } // 测试用网卡mac地址
#else
#define NET_IF_IP         \
    {                     \
        10, 250, 123, 233 \
    } // 自定义网卡ip地址
#define NET_IF_MAC                         \
    {                                      \
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55 \
    } // 自定义网卡mac地址
#endif

#define ETHERNET_MAX_TRANSPORT_UNIT 1500 // 以太网最大传输单元

#define ARP_TIMEOUT_SEC (60 * 5) // arp表过期时间
#define ARP_MIN_INTERVAL 1       // 向相同地址发送arp请求的最小间隔

#define IP_DEFALUT_TTL 64 // IP默认TTL

#define BUF_MAX_LEN (2 * UINT16_MAX + UINT8_MAX) // buf最大长度

#define MAP_MAX_LEN (16 * BUF_MAX_LEN) // map最大长度

#define NET_BROADCAST_MAC                  \
    {                                      \
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff \
    } // 网络广播的 MAC 地址

#endif

/*
根据 wlp1s0 的信息，我们可以得到：

IP 地址（IPv4）：10.250.123.222
子网掩码：255.255.0.0
广播地址：10.250.255.255

IP 地址（IPv6）：2001:250:3c0f:2000::4bce（全局范围）
IPv6 地址（Link-local）：fe80::cd83:3ea2:1183:ed26

MAC 地址：30:c9:ab:d3:1e:ff
*/