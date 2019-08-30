/*
** Copyright (C) 2009-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2019 Adam Hall <ahall@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* check-flow.c */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "rules.h"
#include "sagan-config.h"

struct _Rule_Struct *rulestruct;
struct RuleHead *RuleHead;

/********************/ /***********************/ /*******************/
/***** flow_type ****/ /*** keyword_address ***/ /***  direction  ***/
/* 0 = not in group */ /**     0 = no        **/ /**    0 = any    **/
/* 1 = in group     */ /**     1 = any       **/ /**    1 = right  **/
/* 2 = not match ip */ /**     2 = unknown   **/ /**    2 = left   **/
/* 3 = match ip     */ /***********************/ /*******************/
/********************/ /***********************/ /*******************/

bool Check_Flow( int b, int ip_proto, unsigned char *ip_src_bits, int normalize_src_port, unsigned char *ip_dst_bits, int normalize_dst_port)
{

    unsigned char *src;
    unsigned char *dst;

    int port_src;
    int port_dst;

    unsigned char *ip_src;
    unsigned char *ip_dst;

    src = ip_src_bits;
    dst = ip_dst_bits;

    unsigned char ip_convert[MAXIPBIT] = { 0 };

    if(RuleHead[b].direction == 0 || RuleHead[b].direction == 1)
        {
            ip_src = src;
            ip_dst = dst;
            port_src = normalize_src_port;
            port_dst = normalize_dst_port;
        }
    else
        {
            ip_src = dst;
            ip_dst = src;
            port_src = normalize_dst_port;
            port_dst = normalize_src_port;
        }


    /*proto*/

    int c1=0;

    /*flow 1*/

    int w=0;
    int a1=0;
    int eq1=0;
    int ne1=0;
    int eq1_val=0;
    int ne1_val=0;
    int f1;

    /*port 1*/

    int b1=0;
    int u=0;
    int eq3=0;
    int ne3=0;
    int eq3_val=0;
    int ne3_val=0;
    int g1;


    /*flow 2*/

    int z=0;
    int a2=0;
    int eq2=0;
    int ne2=0;
    int eq2_val=0;
    int ne2_val=0;
    int f2;

    /*port 2*/

    int b2=0;
    int v=0;
    int eq4=0;
    int ne4=0;
    int eq4_val=0;
    int ne4_val=0;
    int g2;

    int i;
    int failed=0;

    /*Begin ip_proto*/

    if(RuleHead[b].ip_proto != 0) {
            if(ip_proto == RuleHead[b].ip_proto) c1=1;	// Explicit match.
    } else c1=1;	// Match any.

    if(c1 != 1) return 0;	// Unmatched protocol.

    /*Begin flow_1*/

    if(RuleHead[b].target[0].any_address == false) {
        //Sagan_Log(NORMAL, "Flow: processing RuleHead[%d]...", b);
         for(i=0; i < RuleHead[b].target[0].address_count; i++) {
		//Sagan_Log(NORMAL, "\tFlow: processing address %d...", i);
                w++;
                //f1 = rulestruct[b].flow_1_type[w];
                //f1 = RuleHead[b].target[0].address[i].type;
                //f1 = RuleHead[b].target[0].address[i].keyword;	// THIS WILL NOT WORK! FIX IT LATER.
                if (RuleHead[b].target[0].address[i].is_not == true) {

                    if (RuleHead[b].target[0].address[i].maskbits != 0xffffffff) {	// Is range.
                            ne1++;
                            if(is_inrange(ip_src, (unsigned char *)&RuleHead[b].target[0].address[i].ipbits, 1)) ne1_val++;

                    } else {	// Not range.
                        ne1++;
                        memset(ip_convert, 0, MAXIPBIT);
                        memcpy(ip_convert, ip_src, MAXIPBIT);
                        if (!memcmp(ip_convert, RuleHead[b].target[0].address[i].ipbits, MAXIPBIT) ) ne1_val++;
                   }

                } else {	// is_not == false.

                    if (RuleHead[b].target[0].address[i].maskbits != 0xffffffff) {	// Is range.
                        eq1++;
                        if(is_inrange(ip_src, (unsigned char *)&RuleHead[b].target[0].address[i].ipbits, 1)) eq1_val++;

                    } else {	// Not range.
                        eq1++;
                        memset(ip_convert, 0, MAXIPBIT);
                        memcpy(ip_convert, ip_src, MAXIPBIT);
                        if (!memcmp(ip_convert, RuleHead[b].target[0].address[i].ipbits, MAXIPBIT)) eq1_val++;
                    }
               }
          }
    }
    else a1=1;	// any_address == true.

    /* if ne1, did anything match (meaning failed) */

    if(ne1>0) {
        if(ne1_val > 0) failed++;
    }

    /* if eq1, did anything not match meaning failed */

    if(eq1>0) {
        if(eq1_val < 1) failed++;
    }

    /* if either failed, we did not match, no need to check the second flow... we already failed! */

    if(a1 != 1) {
        if(failed > 0) return 0;
    }

    /*Begin port_1*/

    //if(rulestruct[b].port_1_var != 0)
    if(RuleHead[b].target[0].any_port == false) {
        for(i=0; i < RuleHead[b].target[0].port_count; i++) {
            u++;
            if (RuleHead[b].target[0].port[u].is_not == true) {

                if (RuleHead[b].target[0].port[u].high == RuleHead[b].target[0].port[u].low) {	// Not range.
                    ne3++;
                    if(port_src == RuleHead[b].target[0].port[i].low) ne3_val++;

                } else {	// Is range.
                    ne3++;
                    if(port_src >= RuleHead[b].target[0].port[i].low && port_src <= RuleHead[b].target[0].port[i].high) ne3_val++;
                }

            } else {	// is_not == false.

                if (RuleHead[b].target[0].port[u].high == RuleHead[b].target[0].port[u].low) {	// Not range.
                    eq3++;
                    if(port_src == RuleHead[b].target[0].port[i].low) eq3_val++;

                } else {	// Is range.
                    eq3++;
                    if(port_src >= RuleHead[b].target[0].port[i].low && port_src <= RuleHead[b].target[0].port[i].high) eq3_val++;
                }

            }	// is_not.
        }	// for port_count.
    } else b1=1;	// any_port == true.

    /* if ne3, did anything match (meaning failed) */

    if(ne3>0) {
        if(ne3_val > 0) failed++;
    }

    /* if eq3, did anything not match meaning failed */

    if(eq3>0) {
        if(eq3_val < 1) failed++;
    }

    /* if either failed, we did not match, no need to check the second flow... we already failed! */

    if(b1 != 1) {
        if(failed > 0) return 0;
    }



    /* Begin flow_2 */

    if(RuleHead[b].target[1].any_address == false) {

        for(i=0; i < RuleHead[b].target[1].address_count; i++) {
			//Sagan_Log(NORMAL, "\tFlow: processing address %d...", i);
                w++;
                //f1 = rulestruct[b].flow_1_type[w];
                //f1 = RuleHead[b].target[1].address[i].type;
                //f1 = RuleHead[b].target[1].address[i].keyword;	// THIS WILL NOT WORK! FIX IT LATER.
                if (RuleHead[b].target[1].address[i].is_not == true) {

                    if (RuleHead[b].target[1].address[i].maskbits != 0xffffffff) {	// Is range.
                            ne1++;
                            if(is_inrange(ip_src, (unsigned char *)&RuleHead[b].target[1].address[i].ipbits, 1)) ne1_val++;

                    } else {	// Not range.
                        ne1++;
                        memset(ip_convert, 0, MAXIPBIT);
                        memcpy(ip_convert, ip_src, MAXIPBIT);
                        if (!memcmp(ip_convert, RuleHead[b].target[1].address[i].ipbits, MAXIPBIT) ) ne1_val++;
                   }

                } else {	// is_not == false.

                    if (RuleHead[b].target[1].address[i].maskbits != 0xffffffff) {	// Is range.
                        eq1++;
                        if(is_inrange(ip_src, (unsigned char *)&RuleHead[b].target[1].address[i].ipbits, 1)) eq1_val++;

                    } else {	// Not range.
                        eq1++;
                        memset(ip_convert, 0, MAXIPBIT);
                        memcpy(ip_convert, ip_src, MAXIPBIT);
                        if (!memcmp(ip_convert, RuleHead[b].target[1].address[i].ipbits, MAXIPBIT)) eq1_val++;
                    }
               }
          }
    } else a2=1;	// any_address == true.

    /* if ne2, did anything match (meaning failed) */

    if(ne2>0) {
        if(ne2_val > 0) failed++;
    }

    /* if eq2, did anything not match meaning failed */

    if(eq2>0) {
        if(eq2_val < 1) failed++;
    }

    /* if either failed, we did not match, leave */

    if(a2 != 1) {
        if(failed > 0) return 0;
    }

    /*Begin port_2*/

    if(RuleHead[b].target[1].any_port == false) {
        for(i=0; i < RuleHead[b].target[1].port_count; i++) {
            u++;
            if (RuleHead[b].target[1].port[u].is_not == true) {

                if (RuleHead[b].target[1].port[u].high == RuleHead[b].target[1].port[u].low) {	// Not range.
                    ne3++;
                    if(port_src == RuleHead[b].target[1].port[i].low) ne3_val++;

                } else {	// Is range.
                    ne3++;
                    if(port_src >= RuleHead[b].target[1].port[i].low && port_src <= RuleHead[b].target[1].port[i].high) ne3_val++;
                }

            } else {	// is_not == false.

                if (RuleHead[b].target[1].port[u].high == RuleHead[b].target[1].port[u].low) {	// Not range.
                    eq3++;
                    if(port_src == RuleHead[b].target[1].port[i].low) eq3_val++;

                } else {	// Is range.
                    eq3++;
                    if(port_src >= RuleHead[b].target[1].port[i].low && port_src <= RuleHead[b].target[1].port[i].high) eq3_val++;
                }

            }	// is_not.
        }	// for port_count.
    } else b2=1;	// any_port == true.

    /* if ne4, did anything match (meaning failed) */

    if(ne4>0) {
        if(ne4_val > 0) failed++;
    }

    /* if eq4, did anything not match meaning failed */

    if(eq4>0) {
        if(eq4_val < 1) failed++;
    }

    /* if either failed, we did not match, no need to check the second flow... we already failed! */

    if(b2 != 1) {
        if(failed > 0) return 0;
    }

    /* If we made it to this point we have a match */

    return 1;

} /*We are done*/
