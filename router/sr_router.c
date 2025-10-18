#include "sr_router.h"

#include <assert.h>
#include <stdio.h>

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

static int is_to_me(struct sr_instance *sr, uint32_t ip_dst) {
  struct sr_if *iface = sr->if_list;
  while (iface) {
    if (iface->ip == ip_dst) return 1;
    iface = iface->next;
  }
  return 0;
}

static struct sr_rt *lpm_lookup(struct sr_instance *sr, uint32_t ip_dst) {
  struct sr_rt *best = NULL;
  int best_len = -1;
  for (struct sr_rt *rt = sr->routing_table; rt; rt = rt->next) {
    if ((ip_dst & rt->mask.s_addr) == (rt->dest.s_addr & rt->mask.s_addr)) {
      int len = __builtin_popcount(ntohl(rt->mask.s_addr));
      if (len > best_len) {
        best = rt;
        best_len = len;
      }
    }
  }
  return best;
}

static void send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                      char *iface_name, uint8_t type, uint8_t code) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *iface = sr_get_interface(sr, iface_name);
  if (!iface) return;

  uint8_t buf[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
              sizeof(sr_icmp_t3_hdr_t)];
  sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_r =
      (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) +
                           sizeof(sr_ip_hdr_t));

  memcpy(eth_r->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_r->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_r->ether_type = htons(ethertype_ip);

  ip_r->ip_v = 4;
  ip_r->ip_hl = 5;
  ip_r->ip_tos = 0;
  ip_r->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ip_r->ip_id = 0;
  ip_r->ip_off = 0;
  ip_r->ip_ttl = 64;
  ip_r->ip_p = ip_protocol_icmp;
  ip_r->ip_src = iface->ip;
  ip_r->ip_dst = ip->ip_src;
  ip_r->ip_sum = 0;
  ip_r->ip_sum = cksum(ip_r, sizeof(sr_ip_hdr_t));

  icmp_r->icmp_type = type;
  icmp_r->icmp_code = code;
  memcpy(icmp_r->data, ip, ICMP_DATA_SIZE);
  icmp_r->icmp_sum = 0;
  icmp_r->icmp_sum = cksum(icmp_r, sizeof(sr_icmp_t3_hdr_t));

  sr_send_packet(sr, buf, sizeof(buf), iface->name);
}

static void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet,
                                 unsigned int len, char *iface_name) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *iface = sr_get_interface(sr, iface_name);
  if (!iface) return;

  uint8_t reply[len];
  memcpy(reply, packet, len);
  sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)reply;
  sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_r =
      (sr_icmp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  memcpy(eth_r->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_r->ether_shost, iface->addr, ETHER_ADDR_LEN);
  uint32_t tmp = ip_r->ip_src;
  ip_r->ip_src = ip_r->ip_dst;
  ip_r->ip_dst = tmp;
  ip_r->ip_sum = 0;
  ip_r->ip_sum = cksum(ip_r, sizeof(sr_ip_hdr_t));

  icmp_r->icmp_type = 0;
  icmp_r->icmp_code = 0;
  icmp_r->icmp_sum = 0;
  icmp_r->icmp_sum =
      cksum(icmp_r, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

  sr_send_packet(sr, reply, len, iface->name);
}

static void forward_packet(struct sr_instance *sr, uint8_t *packet,
                           unsigned int len, char *in_iface) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  ip->ip_ttl--;
  if (ip->ip_ttl == 0) {
    send_icmp(sr, packet, len, in_iface, 11, 0);
    return;
  }
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));

  struct sr_rt *best = lpm_lookup(sr, ip->ip_dst);
  if (!best) {
    send_icmp(sr, packet, len, in_iface, 3, 0);
    return;
  }
  struct sr_if *out_if = sr_get_interface(sr, best->interface);
  if (!out_if) return;

  uint32_t next_hop = (best->gw.s_addr) ? best->gw.s_addr : ip->ip_dst;
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, next_hop);
  if (entry) {
    sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
    memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    memcpy(eth->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, out_if->name);
    free(entry);
  } else {
    sr_arpcache_queuereq(&sr->cache, next_hop, packet, len, out_if->name);
  }
}

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);
  /* fill in code here */

  if (len < sizeof(sr_ethernet_hdr_t)) {
    return;
  }

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
  uint16_t type = ntohs(eth->ether_type);

  if (type == ethertype_arp) {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) return;
    sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if (ntohs(arp->ar_op) == arp_op_request) {
      struct sr_if *iface = sr_get_interface(sr, interface);
      if (iface && arp->ar_tip == iface->ip) {
        uint8_t buf[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)];
        sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)buf;
        sr_arp_hdr_t *arp_r = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));

        memcpy(eth_r->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_r->ether_shost, iface->addr, ETHER_ADDR_LEN);
        eth_r->ether_type = htons(ethertype_arp);

        arp_r->ar_hrd = htons(arp_hrd_ethernet);
        arp_r->ar_pro = htons(ethertype_ip);
        arp_r->ar_hln = ETHER_ADDR_LEN;
        arp_r->ar_pln = 4;
        arp_r->ar_op = htons(arp_op_reply);
        memcpy(arp_r->ar_sha, iface->addr, ETHER_ADDR_LEN);
        arp_r->ar_sip = iface->ip;
        memcpy(arp_r->ar_tha, arp->ar_sha, ETHER_ADDR_LEN);
        arp_r->ar_tip = arp->ar_sip;

        sr_send_packet(sr, buf, sizeof(buf), iface->name);
      }
    } else if (ntohs(arp->ar_op) == arp_op_reply) {
      sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);
    }
    return;
  }

  if (type != ethertype_ip) return;
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;

  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if (is_to_me(sr, ip->ip_dst)) {
    if (ip->ip_p == ip_protocol_icmp) {
      sr_icmp_hdr_t *icmp =
          (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) +
                            sizeof(sr_ip_hdr_t));
      if (icmp->icmp_type == 8) send_icmp_echo_reply(sr, packet, len, interface);
    } else {
      send_icmp(sr, packet, len, interface, 3, 3);
    }
    return;
  }

  forward_packet(sr, packet, len, interface);

} /* end sr_ForwardPacket */
