#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 *
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    buf_add_header(buf, 12);

    uint8_t ip_header_backup[20];
    memcpy(ip_header_backup, buf->data + 12, 20);

    memcpy(buf->data, src_ip, 4);
    memcpy(buf->data + 4, dst_ip, 4);
    buf->data[8] = 0;
    buf->data[9] = ip_header_backup[9];
    *((uint16_t *)(buf->data + 10)) = *((uint16_t *)(ip_header_backup + 4));

    uint16_t result = checksum16((uint16_t *)buf->data, buf->len);

    memcpy(buf->data + 12, ip_header_backup, 20);
    buf_remove_header(buf, 12);

    return result;
}

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    if (buf->len < 8 || buf->len < *((uint16_t *)(buf->data + 4)))
        return;

    uint16_t received_checksum = *((uint16_t *)(buf->data + 6));
    *((uint16_t *)(buf->data + 6)) = 0;

    uint8_t *dst_ip = buf->data + 16;
    uint16_t calculated_checksum = udp_checksum(buf, src_ip, dst_ip);

    if (received_checksum != calculated_checksum)
        return;

    uint16_t dst_port = *((uint16_t *)(buf->data + 2));

    void (*handler)(buf_t *) = map_get(&udp_table, &dst_port);

    if (!handler)
    {
        buf_add_header(buf, 20);
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
        return;
    }

    buf_remove_header(buf, 8);
    handler(buf);
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_add_header(buf, 8);

    *((uint16_t *)(buf->data)) = src_port;
    *((uint16_t *)(buf->data + 2)) = dst_port;
    *((uint16_t *)(buf->data + 4)) = buf->len;
    *((uint16_t *)(buf->data + 6)) = 0;

    uint8_t src_ip[4];
    memcpy(src_ip, net_if_ip, 4);

    uint16_t checksum = udp_checksum(buf, src_ip, dst_ip);
    *((uint16_t *)(buf->data + 6)) = checksum;

    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}