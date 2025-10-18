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

static int is_to_me(struct sr_instance *sr, uint32_t ip_dst) {
  struct sr_if *iface = sr->if_list;
  while (iface) {
    if (iface->ip == ip_dst) return 1;
    iface = iface->next;
  }
  return 0;
}

static void build_and_send_icmp_t3(struct sr_instance *sr, uint8_t *rx_pkt, unsigned int rx_len, char *in_iface, uint8_t code) {
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)rx_pkt;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(rx_pkt + sizeof(sr_ethernet_hdr_t));
  uint8_t buf[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
  sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_r = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  struct sr_if *out_if = sr_get_interface(sr, in_iface);
  if (!out_if) return;
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
  icmp_r->icmp_code = code;
  icmp_r->unused = 0;
  icmp_r->next_mtu = 0;
  memset(icmp_r->data, 0, ICMP_DATA_SIZE);
  memcpy(icmp_r->data, ip, ICMP_DATA_SIZE);
  icmp_r->icmp_sum = 0;
  icmp_r->icmp_sum = cksum(icmp_r, sizeof(sr_icmp_t3_hdr_t));
  sr_send_packet(sr, buf, sizeof(buf), out_if->name);
}

static void build_and_send_icmp_t11(struct sr_instance *sr, uint8_t *rx_pkt, unsigned int rx_len, char *in_iface) {
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)rx_pkt;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(rx_pkt + sizeof(sr_ethernet_hdr_t));
  uint8_t buf[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
  sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_r = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  struct sr_if *out_if = sr_get_interface(sr, in_iface);
  if (!out_if) return;
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
  icmp_r->unused = 0;
  icmp_r->next_mtu = 0;
  memset(icmp_r->data, 0, ICMP_DATA_SIZE);
  memcpy(icmp_r->data, ip, ICMP_DATA_SIZE);
  icmp_r->icmp_sum = 0;
  icmp_r->icmp_sum = cksum(icmp_r, sizeof(sr_icmp_t3_hdr_t));
  sr_send_packet(sr, buf, sizeof(buf), out_if->name);
}

static void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *rx_pkt, unsigned int len, char *in_iface, unsigned int ip_hdr_len) {
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)rx_pkt;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(rx_pkt + sizeof(sr_ethernet_hdr_t));
  struct sr_if *iface = sr_get_interface(sr, in_iface);
  if (!iface) return;
  uint8_t reply[len];
  memcpy(reply, rx_pkt, len);
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

static struct sr_rt *lpm_lookup(struct sr_instance *sr, uint32_t ip_dst) {
  struct sr_rt *best = NULL;
  for (struct sr_rt *rt = sr->routing_table; rt; rt = rt->next) {
    if ((ip_dst & rt->mask.s_addr) == (rt->dest.s_addr & rt->mask.s_addr)) {
      if (!best || ntohl(rt->mask.s_addr) > ntohl(best->mask.s_addr)) best = rt;
    }
  }
  return best;
}

static void forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *in_iface) {
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  unsigned int ip_hdr_len = ip->ip_hl * 4;
  if (ip->ip_ttl <= 1) { build_and_send_icmp_t11(sr, packet, len, in_iface); return; }
  struct sr_rt *best = lpm_lookup(sr, ip->ip_dst);
  if (!best) { build_and_send_icmp_t3(sr, packet, len, in_iface, 0); return; }
  struct sr_if *out_if = sr_get_interface(sr, best->interface);
  if (!out_if) return;
  ip->ip_ttl -= 1;
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, ip_hdr_len);
  uint32_t next_hop_ip = best->gw.s_addr == 0 ? ip->ip_dst : best->gw.s_addr;
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
  if (entry) {
    memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    memcpy(eth->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, out_if->name);
    free(entry);
  } else {
    sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, out_if->name);
  }
}

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

  int to_me = is_to_me(sr, ip->ip_dst);

  if (to_me) {
    if (ip->ip_p == ip_protocol_icmp) {
      sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);
      if (icmp->icmp_type == 8) {
        send_icmp_echo_reply(sr, packet, len, interface, ip_hdr_len);
      }
    } else {
      build_and_send_icmp_t3(sr, packet, len, interface, 3);
    }
    return;
  }

  if (ip->ip_ttl <= 1) {
    build_and_send_icmp_t11(sr, packet, len, interface);
    return;
  }

  forward_packet(sr, packet, len, interface);

} /* end sr_ForwardPacket */
