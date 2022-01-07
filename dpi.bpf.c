// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    dpi

/*
 * works on IPv6 packets
 * assumes that a program (usually, the classifier) has
 * already parsed the program up to the network layer
 * i.e. cur->nhoff is set
 *
 * TODO : may be some errors could be handled instead of dropping
 * packet, considering that this is a debug tool
 * 
 * TODO : we could improve the printing by buffering different print
 * and the making a single print
 * 
 * TODO : print TCP ports
 */

#define HIKE_DEBUG 1

#define REAL
//#define REPL

#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/seg6.h>
#include <linux/errno.h>

#ifdef REAL
  #include "tb_defs.h"
  #include "hike_vm.h"
  #include "parse_helpers.h"
  #include "ip6_hset.h"
#endif  

#ifdef REPL
  #define HIKE_DEBUG 1 
  #include "tb_defs.h"
  #include "ip6_hset_repl.h"
  #include "mock.h"

#endif

#define LAYER_2 1
#define NET_LAYER 2
#define TRANSP_LAYER 4

/* show_pkt_info ()
 * 
 * 
 * 
 * input:
 * - ARG1:	HIKe Program ID;
 * - ARG2:  which parts of the packet needs to be printed
 * - ARG3:  user supplied info
 *
 * 
*/
HIKE_PROG(HIKE_PROG_NAME) {

  struct pkt_info *info;
  struct hdr_cursor *cur;

  union { 
    struct ethhdr *eth_h;
    struct ipv6hdr *ip6h;
    struct udphdr *udph;
    struct tcphdr *tcph;
#define eth_h hdr.eth_h
#define ip6h  hdr.ip6h
#define udph  hdr.udph
#define tcph  hdr.tcph
  } hdr;

  int select_layers = HVM_ARG2;
  int user_info = HVM_ARG3;
    
  
  int offset = 0;
  int ret;

  __u64 display;
  __u64 display2;
  __u16 udp_len;

  /* retrieve packet information from HIKe shared memory*/
  info = hike_pcpu_shmem();
  if (unlikely(!info))
    goto drop;

  /* take the reference to the cursor object which has been saved into
   * the HIKe shared memory
   */
  cur = pkt_info_cur(info);
  /* no need for checking cur != NULL here */

  // ipv6_find_hdr is defined in parse_helpers.h
  ret = ipv6_find_hdr(ctx, cur, &offset, -1, NULL, NULL);
  if (unlikely(ret < 0)) {
    switch (ret) {
    case -ENOENT:
      /* fallthrough */
    case -ELOOP:
      /* fallthrough */
    case -EOPNOTSUPP:
      DEBUG_HKPRG_PRINT("No Transport Info; error: %d", ret);
      goto out;
    default:
      DEBUG_HKPRG_PRINT("Unrecoverable error: %d", ret);
      goto drop;
    }
  }

  DEBUG_HKPRG_PRINT("-------------> ret : %d", ret);

  if (ret != IPPROTO_UDP) {
    DEBUG_HKPRG_PRINT("Transport <> UDP : %d", ret);
    goto out;
  }

  udph = (struct udphdr *)cur_header_pointer(ctx, cur, offset,
                                             sizeof(*udph));
  if (unlikely(!udph)) 
    goto drop;

  udp_len = bpf_ntohs(udph->len) ;
  DEBUG_HKPRG_PRINT("UDP len: %d", udp_len);

  DEBUG_HKPRG_PRINT("User info : %llu",user_info);

out:
	return HIKE_XDP_VM;

drop:
  DEBUG_HKPRG_PRINT("drop packet");
	return HIKE_XDP_ABORTED;

#undef eth_h 
#undef ip6h  
#undef udph  
#undef tcph  
}
//EXPORT_HIKE_PROG(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_3(HIKE_PROG_NAME, __u64, select_layers, __u64, user_info);

/* Export const */
EXPORT_HIKE_CONST(LAYER_2);
EXPORT_HIKE_CONST(NET_LAYER);
EXPORT_HIKE_CONST(TRANSP_LAYER);


#ifdef REAL
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif
