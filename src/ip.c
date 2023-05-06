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
    if (buf->len < ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE)
    {
        return;
    }
    if (ip_hdr->version != IP_VERSION_4 || swap16(ip_hdr->total_len16) > buf->len)
    {
        return;
    }
    uint16_t checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    if (checksum16((uint16_t *)ip_hdr, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE) != checksum)
    {
        return;
    }
    ip_hdr->hdr_checksum16 = checksum;
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0)
    {
        return;
    }
    if (buf->len > swap16(ip_hdr->total_len16))
    {
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));
    }
    // TODO: icmp_unreachable
    if (!(ip_hdr->protocol == NET_PROTOCOL_ICMP || ip_hdr->protocol == NET_PROTOCOL_TCP || ip_hdr->protocol == NET_PROTOCOL_UDP))
    {
        icmp_unreachable(buf, src_mac, ICMP_CODE_PROTOCOL_UNREACH);
    }
    buf_remove_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
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
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    buf_add_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
    ip_hdr->hdr_len = IP_HDR_LEN_PER_BYTE;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    uint16_t flags_fragment = offset & 0x1fffffff;
    if(mf == 1) flags_fragment |= IP_MORE_FRAGMENT;
    ip_hdr->flags_fragment16 = swap16(flags_fragment);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    ip_hdr->hdr_checksum16 = swap16(checksum16((uint16_t *)ip_hdr, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE));
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    const size_t IP_MAX_PAYLOAD_LEN = 1500 - IP_HDR_LEN_PER_BYTE * 5;
    if (buf->len > IP_MAX_PAYLOAD_LEN)
    {
        buf_t ip_buf;
        buf_init(&ip_buf, buf->len);
        buf_copy(ip_buf.data, buf->data, buf->len);
        int offset = 0;
        while (ip_buf.len > IP_MAX_PAYLOAD_LEN)
        {
            ip_fragment_out(&ip_buf, ip, protocol, 0, offset, 1);
            offset += IP_MAX_PAYLOAD_LEN;
            buf_remove_header(&ip_buf, IP_MAX_PAYLOAD_LEN);
        }
        ip_fragment_out(&ip_buf, ip, protocol, 0, offset, 0);
    }
    else
    {
        ip_fragment_out(buf, ip, protocol, 0, 0, 0);
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}