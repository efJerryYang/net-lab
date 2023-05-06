#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    if (buf->len < sizeof(ip_hdr_t))
        return;

    if (ip_hdr->version != IP_VERSION_4 || swap16(ip_hdr->total_len16) > buf->len)
        return;

    uint16_t checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;

    if (swap16(checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t))) != checksum)
        return;

    ip_hdr->hdr_checksum16 = checksum;

    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0)
        return;

    if (buf->len > swap16(ip_hdr->total_len16))
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));

    if (!(ip_hdr->protocol == NET_PROTOCOL_ICMP || ip_hdr->protocol == NET_PROTOCOL_TCP || ip_hdr->protocol == NET_PROTOCOL_UDP))
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);

    buf_remove_header(buf, sizeof(ip_hdr_t));

    net_in(buf, ip_hdr->protocol, ip_hdr->src_ip);
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    buf_add_header(buf, sizeof(ip_hdr_t)); // Order of this line matters
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    uint16_t flags_fragment = (offset & 0x1fffffff) | (mf << 13);
    ip_hdr->flags_fragment16 = swap16(flags_fragment);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
int packet_id = 0;

void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    size_t max_fragment_len = 1500 - sizeof(ip_hdr_t);
    size_t total_data_len = buf->len;

    if (total_data_len > max_fragment_len)
    {
        size_t data_offset = 0;
        int fragment_index = 0;
        int has_more_fragments = 1;

        while (total_data_len > 0)
        {
            size_t current_fragment_len = (total_data_len > max_fragment_len) ? max_fragment_len : total_data_len;
            has_more_fragments = (total_data_len > max_fragment_len);

            buf_t fragment_buf;
            buf_init(&fragment_buf, current_fragment_len);
            memcpy(fragment_buf.data, buf->data + data_offset, current_fragment_len);

            ip_fragment_out(&fragment_buf, ip, protocol, packet_id, fragment_index * (max_fragment_len >> 3), has_more_fragments);

            data_offset += current_fragment_len;
            total_data_len -= current_fragment_len;
            fragment_index++;
        }
    }
    else
    {
        ip_fragment_out(buf, ip, protocol, packet_id, 0, 0);
    }
    packet_id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}