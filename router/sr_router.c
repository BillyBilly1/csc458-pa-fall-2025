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
  printf("[ICMP-T3] req-iface=%s code=%u rx_len=%u\n", in_iface, code, rx_len);
  if (rx_len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) { printf("[ICMP-T3] drop: rx too short\n"); return; }
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)rx_pkt;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(rx_pkt + sizeof(sr_ethernet_hdr_t));
  uint8_t buf[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
  sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_r = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  struct sr_if *out_if = sr_get_interface(sr, in_iface);
  if (!out_if) { printf("[ICMP-T3] no out_if for %s\n", in_iface); return; }

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

  printf("[ICMP-T3] send iface=%s src_ip=%08x dst_ip=%08x len=%zu\n",
         out_if->name, ntohl(ip_r->ip_src), ntohl(ip_r->ip_dst), sizeof(buf));
  sr_send_packet(sr, buf, sizeof(buf), out_if->name);
}

static void build_and_send_icmp_t11(struct sr_instance *sr, uint8_t *rx_pkt, unsigned int rx_len, char *in_iface) {
  printf("[ICMP-T11] req-iface=%s rx_len=%u\n", in_iface, rx_len);
  if (rx_len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) { printf("[ICMP-T11] drop: rx too short\n"); return; }
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)rx_pkt;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(rx_pkt + sizeof(sr_ethernet_hdr_t));
  uint8_t buf[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
  sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_r = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  struct sr_if *out_if = sr_get_interface(sr, in_iface);
  if (!out_if) { printf("[ICMP-T11] no out_if for %s\n", in_iface); return; }

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

  printf("[ICMP-T11] send iface=%s src_ip=%08x dst_ip=%08x len=%zu\n",
         out_if->name, ntohl(ip_r->ip_src), ntohl(ip_r->ip_dst), sizeof(buf));
  sr_send_packet(sr, buf, sizeof(buf), out_if->name);
}

static void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *rx_pkt, unsigned int len, char *in_iface, unsigned int ip_hdr_len) {
  printf("[ICMP-ECHO] iface=%s len=%u ihl=%u\n", in_iface, len, ip_hdr_len);
  if (len < sizeof(sr_ethernet_hdr_t) + ip_hdr_len + sizeof(sr_icmp_hdr_t)) { printf("[ICMP-ECHO] drop: too short\n"); return; }
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)rx_pkt;
  struct sr_if *iface = sr_get_interface(sr, in_iface);
  if (!iface) { printf("[ICMP-ECHO] no iface\n"); return; }

  uint8_t reply[len];
  memcpy(reply, rx_pkt, len);
  sr_ethernet_hdr_t *eth_r = (sr_ethernet_hdr_t *)reply;
  sr_ip_hdr_t *ip_r = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_r = (sr_icmp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);

  memcpy(eth_r->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_r->ether_shost, iface->addr, ETHER_ADDR_LEN);

  uint32_t tmp = ip_r->ip_src;
  ip_r->ip_src = ip_r->ip_dst;
  ip_r->ip_dst = tmp;
  ip_r->ip_sum = 0;
  ip_r->ip_sum = cksum(ip_r, ip_hdr_len);

  icmp_r->icmp_type = 0;
  icmp_r->icmp_code = 0;
  icmp_r->icmp_sum = 0;
  icmp_r->icmp_sum = cksum(icmp_r, len - sizeof(sr_ethernet_hdr_t) - ip_hdr_len);

  printf("[ICMP-ECHO] send iface=%s ip_src=%08x ip_dst=%08x\n", iface->name, ntohl(ip_r->ip_src), ntohl(ip_r->ip_dst));
  sr_send_packet(sr, reply, len, iface->name);
}

static struct sr_rt *lpm_lookup(struct sr_instance *sr, uint32_t ip_dst) {
  struct sr_rt *best = NULL;
  for (struct sr_rt *rt = sr->routing_table; rt; rt = rt->next) {
    if ((ip_dst & rt->mask.s_addr) == (rt->dest.s_addr & rt->mask.s_addr)) {
      if (!best || ntohl(rt->mask.s_addr) > ntohl(best->mask.s_addr)) best = rt;
    }
  }
  if (best) {
    printf("[LPM] hit: dest=%08x mask=%08x gw=%08x iface=%s\n",
           ntohl(best->dest.s_addr), ntohl(best->mask.s_addr), ntohl(best->gw.s_addr), best->interface);
  } else {
    printf("[LPM] miss for dst=%08x\n", ntohl(ip_dst));
  }
  return best;
}

static void forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *in_iface) {
  printf("[FWD] enter len=%u in_iface=%s\n", len, in_iface);
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) { printf("[FWD] drop: too short\n"); return; }

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  unsigned int ip_hdr_len = ip->ip_hl * 4;

  printf("[FWD] ip_src=%08x ip_dst=%08x ttl=%d proto=%d ihl=%u\n",
         ntohl(ip->ip_src), ntohl(ip->ip_dst), ip->ip_ttl, ip->ip_p, ip_hdr_len);

  if (ip->ip_ttl <= 1) { printf("[FWD] ttl<=1 -> ICMP time exceeded\n"); build_and_send_icmp_t11(sr, packet, len, in_iface); return; }

  struct sr_rt *best = lpm_lookup(sr, ip->ip_dst);
  if (!best) { printf("[FWD] no route -> ICMP net unreachable\n"); build_and_send_icmp_t3(sr, packet, len, in_iface, 0); return; }

  struct sr_if *out_if = sr_get_interface(sr, best->interface);
  if (!out_if) { printf("[FWD] no out_if for %s\n", best->interface); return; }

  ip->ip_ttl -= 1;
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, ip_hdr_len);

  uint32_t next_hop_ip = best->gw.s_addr == 0 ? ip->ip_dst : best->gw.s_addr;
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);

  if (entry) {
    uint8_t sendbuf[len];
    memcpy(sendbuf, packet, len);
    sr_ethernet_hdr_t *eth_f = (sr_ethernet_hdr_t *)sendbuf;
    memcpy(eth_f->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    memcpy(eth_f->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    printf("[FWD] ARP hit -> send iface=%s next_hop=%08x ttl=%d dmac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           out_if->name, ntohl(next_hop_ip), ip->ip_ttl,
           eth_f->ether_dhost[0], eth_f->ether_dhost[1], eth_f->ether_dhost[2],
           eth_f->ether_dhost[3], eth_f->ether_dhost[4], eth_f->ether_dhost[5]);
    sr_send_packet(sr, sendbuf, len, out_if->name);
    free(entry);
  } else {
    printf("[FWD] ARP miss -> queue req iface=%s next_hop=%08x\n", out_if->name, ntohl(next_hop_ip));
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
  setvbuf(stdout, NULL, _IONBF, 0);

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
  printf("[INIT] ready. ifaces:\n");
  for (struct sr_if *it = sr->if_list; it; it = it->next) {
    printf("[INIT] %s ip=%08x mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           it->name, ntohl(it->ip),
           it->addr[0], it->addr[1], it->addr[2], it->addr[3], it->addr[4], it->addr[5]);
  }

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

  printf("*** -> Received packet of length %d on iface=%s\n", len, interface);

  if (len < sizeof(sr_ethernet_hdr_t)) {
    printf("[DROP] too short for ethernet header\n");
    return;
  }

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
  uint16_t ethtype = ntohs(eth->ether_type);
  printf("[ETH] type=0x%04x shost=%02x:%02x:%02x:%02x:%02x:%02x dhost=%02x:%02x:%02x:%02x:%02x:%02x\n",
         ethtype,
         eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],
         eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5],
         eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],
         eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);

  /*---------------------------------------------------------------------
   * Handle ARP packets
   *---------------------------------------------------------------------*/
  if (ethtype == ethertype_arp) {
    printf("[ARP] rx\n");
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) { printf("[ARP] drop: too short\n"); return; }
    sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    printf("[ARP] op=%u sip=%08x tip=%08x\n", ntohs(arp->ar_op), ntohl(arp->ar_sip), ntohl(arp->ar_tip));

    if (ntohs(arp->ar_op) == arp_op_request) {
      struct sr_if *iface = sr_get_interface(sr, interface);
      if (iface && arp->ar_tip == iface->ip) {
        printf("[ARP] reply on %s\n", iface->name);
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
      printf("[ARP] reply -> insert cache sip=%08x\n", ntohl(arp->ar_sip));
      sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);
    }
    return;
  }

  /*---------------------------------------------------------------------
   * Handle IP packets
   *---------------------------------------------------------------------*/
  if (ethtype != ethertype_ip) {
    printf("[DROP] not IP, type=0x%04x\n", ethtype);
    return;
  }

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    printf("[IP] drop: too short\n");
    return;
  }

  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  unsigned int ip_hdr_len = ip->ip_hl * 4;
  if (ip_hdr_len < 20) { printf("[IP] drop: ihl<20\n"); return; }
  if (len < sizeof(sr_ethernet_hdr_t) + ip_hdr_len) { printf("[IP] drop: payload shorter than ihl\n"); return; }

  uint16_t old_sum = ip->ip_sum;
  ip->ip_sum = 0;
  uint16_t calc_sum = cksum(ip, ip_hdr_len);
  ip->ip_sum = old_sum;
  if (calc_sum != old_sum) {
    printf("[IP] bad checksum: calc=0x%04x pkt=0x%04x -> drop\n", calc_sum, old_sum);
    return;
  }

  printf("[IP] src=%08x dst=%08x ttl=%d proto=%d ihl=%u total=%u\n",
         ntohl(ip->ip_src), ntohl(ip->ip_dst), ip->ip_ttl, ip->ip_p, ip_hdr_len, ntohs(ip->ip_len));

  int to_me = is_to_me(sr, ip->ip_dst);
  if (to_me) {
    printf("[IP] to router itself\n");
    if (ip->ip_p == ip_protocol_icmp) {
      if (len >= sizeof(sr_ethernet_hdr_t) + ip_hdr_len + sizeof(sr_icmp_hdr_t)) {
        sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);
        printf("[ICMP] type=%u code=%u\n", icmp->icmp_type, icmp->icmp_code);
        if (icmp->icmp_type == 8) {
          send_icmp_echo_reply(sr, packet, len, interface, ip_hdr_len);
        } else {
          printf("[ICMP] not echo request -> ignore\n");
        }
      } else {
        printf("[ICMP] drop: too short for icmp header\n");
      }
    } else {
      printf("[IP] to_me non-ICMP -> ICMP port unreachable\n");
      build_and_send_icmp_t3(sr, packet, len, interface, 3);
    }
    return;
  }

  if (ip->ip_ttl <= 1) {
    printf("[IP] ttl<=1 to forward -> ICMP time exceeded\n");
    build_and_send_icmp_t11(sr, packet, len, interface);
    return;
  }

  printf("[IP] forward path\n");
  forward_packet(sr, packet, len, interface);

} /* end sr_ForwardPacket */
