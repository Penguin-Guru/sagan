/*
** Copyright (C) 2009-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2019 Champ Clark III <cclark@quadrantsec.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef WITH_BLUEDOT
#define BLUEDOT_MAX_CAT        10
#endif

#include <stdbool.h>	// Not sure why my text editor says this is needed for bool declarations in some structures but not others...

typedef struct _Rules_Loaded _Rules_Loaded;
struct _Rules_Loaded
{
    char ruleset[MAXPATH];
};



struct TargetAddress {
	unsigned char ipbits[MAXIPBIT];
	unsigned char maskbits[MAXIPBIT];	// Must come immediately after ipbits due to utility functions.
	bool is_not;
	unsigned short keyword;
	//unsigned short type;	// See comments in "flow.c".
};

struct TargetPort {
	int high;
	int low;
	bool is_not;
	unsigned short keyword;
};

struct RuleHead_Target {
	//unsigned short keyword_address;
	bool any_address;	// See old "flow_var".
	bool any_port;
	int address_count;	// Was "flow_1_counter".
	int port_count;		// Was "port_1_counter".
	//int flow_1_type[MAX_CHECK_FLOWS];
	//int flow_2_type[MAX_CHECK_FLOWS];
	//int port_1_type[MAX_CHECK_FLOWS];
	//int port_2_type[MAX_CHECK_FLOWS];
	struct TargetAddress address[MAX_CHECK_FLOWS];
	struct TargetPort port[MAX_CHECK_FLOWS];
};

struct RuleHead {
	int ruleset_id;
	int action;	// 0 = unspecified, 1 = alert, 2 = drop.
	int ip_proto;                               /*protocol to match against events*/
	//bool has_flow;
	
	/* Targeting: */
	int direction;
	struct RuleHead_Target target[2];	// Two target fields.
};





struct Email {
	char email[255];
	bool email_flag;
};

struct Flexbit {
    int flexbit_count;				/* Number of flexbits in memory */
    int flexbit_upause_time;			/* Delay to let flexbits settle */
    int flexbit_pause_time;
    unsigned char flexbit_condition_count;	/* Number of isset/isnot within a rule */
    unsigned char flexbit_set_count;		/* Number of set/unset within a rule */
    unsigned char flexbit_count_count;		/* Number of count within a rule */

    bool flexbit_flag;              	        /* Does the rule contain a flexbit? */
    bool flexbit_noalert;                       /* Do we want to suppress "alerts" from flexbits in ALL output plugins? */
    bool flexbit_nounified2;                    /* Do we want to suppress "unified2" from flexbits in unified2 output */
    bool flexbit_noeve;				/* Do we want to suppress "eve" from flexbits */

    unsigned char flexbit_type[MAX_FLEXBITS];         /* 1 == set, 2 == unset, 3 == isset, 4 == isnotset, 5 == set_srcport,
						         6 == set_dstport, 7 == set_ports, 8 == count */

    unsigned char flexbit_direction[MAX_FLEXBITS];    /* 0 == none, 1 == both, 2 == by_src, 3 == by_dst */
    int flexbit_timeout[MAX_FLEXBITS];                /* How long a flexbit is to stay alive (seconds) */
    char flexbit_name[MAX_FLEXBITS][64];              /* Name of the flexbit */

    unsigned char flexbit_count_gt_lt[MAX_FLEXBITS];  	/* 0 == Greater, 1 == Less than, 2 == Equals. */
    int flexbit_count_counter[MAX_FLEXBITS];        /* The amount the user is looking for */
    bool flexbit_count_flag;
};

struct Xbit {
    int xbit_count;

    bool xbit_flag;
    bool xbit_noalert;
    bool xbit_noeve;
    bool xbit_nounified2;
    unsigned char xbit_direction[MAX_XBITS];	      /* 1 == ip_src, 2 == ip_dst,  3 == ip_par */

    unsigned char xbit_set_count;            /* Number of set within a rule */
    unsigned char xbit_unset_count;
    unsigned char xbit_isset_count;
    unsigned char xbit_isnotset_count;
    unsigned char xbit_condition_count;
    unsigned char xbit_type[MAX_XBITS];         /* 1 == set, 2 == unset, 3 == isset, 4 == isnotset, 5 == set_srcport,
                                                   6 == set_dstport, 7 == set_ports, 8 == count */

    int xbit_upause_time;
    int xbit_pause_time;

    char xbit_name[MAX_XBITS][64];
    uint32_t xbit_name_hash[MAX_XBITS];
    int xbit_expire[MAX_XBITS];
};

struct Threshold {
    unsigned char threshold_type;               /* 1 = limit,  2 = thresh */
    unsigned char threshold_method;             /* 1 ==  src,  2 == dst,  3 == username, 4 == srcport, 5 == dstport */
    int threshold_count;
    int threshold_seconds;

    unsigned char threshold2_type;               /* 1 = limit,  2 = threshold */
    unsigned char threshold2_method;             /* 1 ==  src,  2 == dst,  3 == username, 4 == srcport, 5 == dstport */
    int threshold2_count;
    int threshold2_seconds;

    bool threshold2_method_src;
    bool threshold2_method_dst;
    bool threshold2_method_username;
    bool threshold2_method_srcport;
    bool threshold2_method_dstport;
};

struct After {
    bool after2;

    bool after2_method_src;
    bool after2_method_dst;
    bool after2_method_username;
    bool after2_method_srcport;
    bool after2_method_dstport;

    int after2_count;
    int after2_seconds;
};

struct AETAS {
	bool alert_time_flag;
	unsigned char alert_days;
	bool aetas_next_day;
	
	int	 aetas_start;
	int  aetas_end;
	
	int  alert_end_hour;
	int  alert_end_minute;
};

struct fwSAM {
	unsigned char fwsam_src_or_dst;             /* 1 == src,  2 == dst */
	unsigned long fwsam_seconds;
};

struct External {
	bool call_program;	// Was "external_flag".
	char program_path[MAXPATH];	// Was "external_program".
};

struct DynamicLoad {
	bool has_dynamic;	// Was "type".
	char  dynamic_ruleset[MAXPATH];
};

//typedef struct meta_content_conversion meta_content_conversion;
//struct meta_content_conversion
struct Meta {
	char meta_content_converted[MAX_META_CONTENT_ITEMS][256];
	int  meta_counter;
};

struct Blacklist {
	//unsigned short affect;	// 1=all, 2=both, 3=bst, 4=src.
	bool blacklist_flag;
	bool blacklist_ipaddr_src;
	bool blacklist_ipaddr_dst;
	bool blacklist_ipaddr_both;
	bool blacklist_ipaddr_all;
};

struct BroIntel {
	bool brointel_flag;

	bool brointel_ipaddr_src;
	bool brointel_ipaddr_dst;
	bool brointel_ipaddr_both;
	bool brointel_ipaddr_all;

	bool brointel_domain;
	bool brointel_file_hash;
	bool brointel_url;
	bool brointel_software;
	bool brointel_email;
	bool brointel_user_name;
	bool brointel_file_name;
	bool brointel_cert_hash;
};

#ifdef WITH_BLUEDOT
struct BlueDot {
	unsigned char   bluedot_ipaddr_type;	// 1 == src,  2 == dst,  3 == both,  4 == all.

	int   bluedot_ip_cats[BLUEDOT_MAX_CAT];
	int   bluedot_ip_cat_count;

	uint64_t bluedot_mdate_effective_period;
	uint64_t bluedot_cdate_effective_period;

	int   bluedot_hash_cats[BLUEDOT_MAX_CAT];
	int   bluedot_hash_cat_count;

	int   bluedot_url_cats[BLUEDOT_MAX_CAT];
	int   bluedot_url_cat_count;

	int   bluedot_filename_cats[BLUEDOT_MAX_CAT];
	int   bluedot_filename_cat_count;

	bool bluedot_file_hash;
	bool bluedot_url;
	bool bluedot_filename;
};
#endif

#ifdef HAVE_LIBMAXMINDDB
struct GeoIP {
	bool geoip2_flag;
	unsigned char geoip2_type;           /* 1 == isnot, 2 == is */
	char  geoip2_country_codes[256];
	unsigned char geoip2_src_or_dst;             /* 1 == src, 2 == dst */
};
#endif

struct RuleBody {
	/* Rule meta-data: */
	uint64_t s_sid;
	uint32_t s_rev;
	char s_reference[MAX_REFERENCE][256];

	/* Output / flow-control: */
	char s_msg[MAX_SAGAN_MSG];
	char s_classtype[32];
	int8_t s_pri;

	/* Stratification "keywords": */
	pcre *re_pcre[MAX_PCRE];
	pcre_extra *pcre_extra[MAX_PCRE];
	char s_content[MAX_CONTENT][256];
	char meta_content[MAX_META_CONTENT][CONFBUF];
	char s_program[256];
	char s_facility[50];
	char s_syspri[25];
	char s_level[25];
	char s_tag[10];
	
	/* Stratification modifiers: */
	bool s_nocase[MAX_CONTENT];
	int s_offset[MAX_CONTENT];
	int s_depth[MAX_CONTENT];
	int s_distance[MAX_CONTENT];
	int s_within[MAX_CONTENT];
	int meta_offset[MAX_META_CONTENT];
	int meta_depth[MAX_META_CONTENT];
	int meta_distance[MAX_META_CONTENT];
	int meta_within[MAX_META_CONTENT];

	/* Flags: */	
	bool content_not[MAX_CONTENT];
	//bool meta_content_flag;
	bool meta_content_case[MAX_META_CONTENT];
	bool meta_content_not[MAX_META_CONTENT];
	bool normalize;

	//char meta_content_help[MAX_META_CONTENT][CONFBUF];

	/* Counters: */
	unsigned char pcre_count;
	unsigned char content_count;
	unsigned char meta_content_count;
	int ref_count;
	//unsigned char meta_content_converted_count;

	/* Defaults: *	// Not currently needed.
	int default_src_port;
	int default_dst_port;
	int default_proto;*/

	/* Parsing control: */
	bool s_find_port;
	bool s_find_proto;
	bool s_find_proto_program;
	bool s_find_src_ip;
	bool s_find_dst_ip;
	int s_find_src_pos;
	int s_find_dst_pos;
	int s_find_hash_type;

	/* Defining these "keywords" as structures helps with readability and streamlines future support for multaple instances as defined per rule. */
	struct Email Email;
	struct Flexbit Flexbit;
	struct Xbit Xbit;
	struct Threshold Threshold;
	struct After After;
	struct AETAS AETAS;
	struct fwSAM fwSAM;
	struct External External;
	struct DynamicLoad DynamicLoad;
	struct Meta Meta[MAX_META_CONTENT];
	struct Blacklist Blacklist;
	struct BroIntel BroIntel;
	#ifdef WITH_BLUEDOT
	struct BlueDot BlueDot;
	#endif
	#ifdef HAVE_LIBMAXMINDDB
	struct GeoIP GeoIP;
	#endif

	//struct meta_content_conversion meta_content_containers[MAX_META_CONTENT];
};


typedef struct _Sagan_Ruleset_Track _Sagan_Ruleset_Track;
struct _Sagan_Ruleset_Track
{
    char ruleset[MAXPATH];
    bool trigger;
};


void Load_Rules (const char *);
unsigned short ParseLine (char *, int, char *, int, int *, char *);
void ParseRule (char *, char *);

void ParseRuleHead (char *, int);
void PrintRuleHeadDebug ();
void PrintRuleTargetDebug (int);

bool ParseTargetAddress (char *, int);
bool ParseTargetPort (char *, int);
bool ExceedFlows (int *, char[10]);
bool ParseDirection (char *);

void ParseRuleBody (char *, int, char *);
void ParseRuleBodyDebug ();

bool ParseRuleKey_Classtype (char *, char *);
bool ParseRuleKey_Content (char *, char *);
bool ParseRuleKey_Msg (char *, char *);
bool ParseRuleKey_ParsePort (char *, char *);
bool ParseRuleKey_ParseProto (char *, char *);
bool ParseRuleKey_ParseProtoProgram (char *, char *);
bool ParseRuleKey_Program (char *, char *);
bool ParseRuleKey_Rev (char *, char *);
bool ParseRuleKey_Sid (char *, char *);
