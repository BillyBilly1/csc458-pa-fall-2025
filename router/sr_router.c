#include "sr_router.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  if (len < sizeof(sr_ethernet_hdr_t)) {
    return;
  }

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
  uint16_t ethtype = ntohs(eth->ether_type);

  /*---------------------------------------------------------------------
   * Handle ARP packets
   *---------------------------------------------------------------------*/
  if (ethtype == ethertype_arp) {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
      return;
    }
    sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    if (ntohs(arp->ar_op) == arp_op_request) {
      struct sr_if *iface = sr_get_interface(sr, interface);
      if (iface && arp->ar_tip == iface->ip) {
        uint8_t reply_packet[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)];
        sr_ethernet_hdr_t *eth_reply = (sr_ethernet_hdr_t *)reply_packet;
        sr_arp_hdr_t *arp_reply = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));

        memcpy(eth_reply->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_reply->ether_shost, iface->addr, ETHER_ADDR_LEN);
        eth_reply->ether_type = htons(ethertype_arp);

        arp_reply->ar_hrd = htons(arp_hrd_ethernet);
        arp_reply->ar_pro = htons(ethertype_ip);
        arp_reply->ar_hln = ETHER_ADDR_LEN;
        arp_reply->ar_pln = 4;
        arp_reply->ar_op = htons(arp_op_reply);
        memcpy(arp_reply->ar_sha, iface->addr, ETHER_ADDR_LEN);
        arp_reply->ar_sip = iface->ip;
        memcpy(arp_reply->ar_tha, arp->ar_sha, ETHER_ADDR_LEN);
        arp_reply->ar_tip = arp->ar_sip;

        sr_send_packet(sr, reply_packet, sizeof(reply_packet), iface->name);
      }
    } else if (ntohs(arp->ar_op) == arp_op_reply) {
      sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);
    }
    return;
  }

  /*---------------------------------------------------------------------
   * Handle IP packets
   *---------------------------------------------------------------------*/
  if (ethtype != ethertype_ip) {
    return;
  }

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return;
  }

  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  unsigned int ip_hdr_len = ip->ip_hl * 4;
  if (ip_hdr_len < 20) {
    return;
  }

  if (len < sizeof(sr_ethernet_hdr_t) + ip_hdr_len) {
    return;
  }

  uint16_t old_sum = ip->ip_sum;
  ip->ip_sum = 0;
  uint16_t calc_sum = cksum(ip, ip_hdr_len);
  ip->ip_sum = old_sum;
  if (calc_sum != old_sum) {
    return;
  }

  int to_me = 0;
  struct sr_if *iface = sr->if_list;
  while (iface) {
    if (iface->ip == ip->ip_dst) {
      to_me = 1;
      break;
    }
    iface = iface->next;
  }

  if (to_me) {
    if (ip->ip_p == ip_protocol_icmp) {
      sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);
      if (icmp->icmp_type == 8) {
        uint8_t reply[len];
        memcpy(reply, packet, len);

        sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)reply;
        sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
        sr_icmp_hdr_t *icmp_r = (sr_icmp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);

        memcpy(eth_r->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_r->ether_shost, iface->addr, ETHER_ADDR_LEN);

        uint32_t temp = ip_r->ip_src;
        ip_r->ip_src = ip_r->ip_dst;
        ip_r->ip_dst = temp;
        ip_r->ip_sum = 0;
        ip_r->ip_sum = cksum(ip_r, ip_hdr_len);

        icmp_r->icmp_type = 0;
        icmp_r->icmp_code = 0;
        icmp_r->icmp_sum = 0;
        icmp_r->icmp_sum = cksum(icmp_r, len - sizeof(sr_ethernet_hdr_t) - ip_hdr_len);

        sr_send_packet(sr, reply, len, iface->name);
      }
    } else {
      uint8_t buf[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
      sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)buf;
      sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
      sr_icmp_t3_hdr_t *icmp_r = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      struct sr_if *out_if = sr_get_interface(sr, interface);

      memcpy(eth_r->ether_shost, out_if->addr, ETHER_ADDR_LEN);
      memcpy(eth_r->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
      eth_r->ether_type = htons(ethertype_ip);

      ip_r->ip_v = 4;
      ip_r->ip_hl = 5;
      ip_r->ip_tos = 0;
      ip_r->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
      ip_r->ip_id = 0;
      ip_r->ip_off = 0;
      ip_r->ip_ttl = 64;
      ip_r->ip_p = ip_protocol_icmp;
      ip_r->ip_src = out_if->ip;
      ip_r->ip_dst = ip->ip_src;
      ip_r->ip_sum = 0;
      ip_r->ip_sum = cksum(ip_r, sizeof(sr_ip_hdr_t));

      icmp_r->icmp_type = 3;
      icmp_r->icmp_code = 3;
      icmp_r->icmp_sum = 0;
      memcpy(icmp_r->data, ip, ICMP_DATA_SIZE);
      icmp_r->icmp_sum = cksum(icmp_r, sizeof(sr_icmp_t3_hdr_t));

      sr_send_packet(sr, buf, sizeof(buf), out_if->name);
    }
    return;
  }

  if (ip->ip_ttl <= 1) {
    uint8_t buf[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
    sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)buf;
    sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmp_r = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    struct sr_if *out_if = sr_get_interface(sr, interface);

    memcpy(eth_r->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    memcpy(eth_r->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
    eth_r->ether_type = htons(ethertype_ip);

    ip_r->ip_v = 4;
    ip_r->ip_hl = 5;
    ip_r->ip_tos = 0;
    ip_r->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip_r->ip_id = 0;
    ip_r->ip_off = 0;
    ip_r->ip_ttl = 64;
    ip_r->ip_p = ip_protocol_icmp;
    ip_r->ip_src = out_if->ip;
    ip_r->ip_dst = ip->ip_src;
    ip_r->ip_sum = 0;
    ip_r->ip_sum = cksum(ip_r, sizeof(sr_ip_hdr_t));

    icmp_r->icmp_type = 11;
    icmp_r->icmp_code = 0;
    icmp_r->icmp_sum = 0;
    memcpy(icmp_r->data, ip, ICMP_DATA_SIZE);
    icmp_r->icmp_sum = cksum(icmp_r, sizeof(sr_icmp_t3_hdr_t));

    sr_send_packet(sr, buf, sizeof(buf), out_if->name);
    return;
  }

  ip->ip_ttl -= 1;
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, ip_hdr_len);

  struct sr_rt *best = NULL;
  for (struct sr_rt *rt = sr->routing_table; rt; rt = rt->next) {
    if ((ip->ip_dst & rt->mask.s_addr) == (rt->dest.s_addr & rt->mask.s_addr)) {
      if (!best || ntohl(rt->mask.s_addr) > ntohl(best->mask.s_addr)) {
        best = rt;
      }
    }
  }

  if (!best) {
    struct sr_if *out_if = sr_get_interface(sr, interface);
    uint8_t buf[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
    sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)buf;
    sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmp_r = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    memcpy(eth_r->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    memcpy(eth_r->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
    eth_r->ether_type = htons(ethertype_ip);

    ip_r->ip_v = 4;
    ip_r->ip_hl = 5;
    ip_r->ip_tos = 0;
    ip_r->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip_r->ip_id = 0;
    ip_r->ip_off = 0;
    ip_r->ip_ttl = 64;
    ip_r->ip_p = ip_protocol_icmp;
    ip_r->ip_src = out_if->ip;
    ip_r->ip_dst = ip->ip_src;
    ip_r->ip_sum = 0;
    ip_r->ip_sum = cksum(ip_r, sizeof(sr_ip_hdr_t));

    icmp_r->icmp_type = 3;
    icmp_r->icmp_code = 0;
    icmp_r->icmp_sum = 0;
    memcpy(icmp_r->data, ip, ICMP_DATA_SIZE);
    icmp_r->icmp_sum = cksum(icmp_r, sizeof(sr_icmp_t3_hdr_t));

    sr_send_packet(sr, buf, sizeof(buf), out_if->name);
    return;
  }

  uint32_t next_hop_ip = best->gw.s_addr == 0 ? ip->ip_dst : best->gw.s_addr;
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
  if (entry) {
    struct sr_if *out_if = sr_get_interface(sr, best->interface);
    if (!out_if) return;
    memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    memcpy(eth->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, out_if->name);
    free(entry);
  } else {
  sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, out_if->name);
  }


} /* end sr_ForwardPacket */
