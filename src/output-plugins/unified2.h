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
#include "config.h"
#endif

/* sagan-unified2.h  */

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

#include <stdint.h>
#include <stdio.h>

#define UNIFIED2_PACKET              2
#define UNIFIED2_IDS_EVENT           7
#define UNIFIED2_IDS_EVENT_IPV6      72
#define UNIFIED2_IDS_EVENT_MPLS      99
#define UNIFIED2_IDS_EVENT_IPV6_MPLS 100
#define UNIFIED2_IDS_EVENT_VLAN      104
#define UNIFIED2_IDS_EVENT_IPV6_VLAN 105
#define UNIFIED2_EXTRA_DATA          110

#define SAGAN_SNPRINTF_ERROR -1
#define SAGAN_SNPRINTF_TRUNCATION 1
#define SAGAN_SNPRINTF_SUCCESS 0
#define SAFEMEM_SUCCESS 1
#define IP_MAXPACKET    65535        /* maximum packet size */

#define SAFEMEM_ERROR 0
#define SAFEMEM_SUCCESS 1

#define ERRORRET return SAFEMEM_ERROR;

#define MAX_XFF_WRITE_BUF_LENGTH (sizeof(Serial_Unified2_Header) + \
        sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData) \
	        + sizeof(struct in6_addr))

#define DECODE_BLEN 65535
#define EVENT_TYPE_EXTRA_DATA   4

void Unified2( _Sagan_Event * );
void Unified2LogPacketAlert( _Sagan_Event * );
void Unified2InitFile( void );
int SaganSnprintf(char *buf, size_t buf_size, const char *format, ...);
void *SaganAlloc( unsigned long );
void Unified2CleanExit( void );
void Unified2WriteExtraData( _Sagan_Event *, int );

/* Data structure used for serialization of Unified2 Records */
typedef struct _Serial_Unified2_Header
{
    uint32_t   type;
    uint32_t   length;
} Serial_Unified2_Header;

//UNIFIED2_PACKET = type 2

typedef struct _Serial_Unified2Packet
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t packet_second;
    uint32_t packet_microsecond;
    uint32_t linktype;
    uint32_t packet_length;
    uint8_t packet_data[4];
} Serial_Unified2Packet;

//---------------LEGACY, type '7'
//These structures are not used anymore in the product

typedef struct _Serial_Unified2IDSEvent_legacy
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  impact_flag;//sets packet_action
    uint8_t  impact;
    uint8_t  blocked;
} Serial_Unified2IDSEvent_legacy;

typedef struct _Serial_Unified2IDSEventIPv6_legacy
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    struct in6_addr ip_source;
    struct in6_addr ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  impact_flag;
    uint8_t  impact;
    uint8_t  blocked;
} Serial_Unified2IDSEventIPv6_legacy;

#define UNIFIED_SET(legacy, type, member, value) { \
    if (type == UNIFIED2_IDS_EVENT_IPV6) { \
        ((Serial_Unified2IDSEventIPv6_legacy *)legacy)->member = value; \
    } else { \
        ((Serial_Unified2IDSEvent_legacy *)legacy)->member = value; \
    } \
}
#define UNIFIED_OFF(legacy, type, member) ( \
    type == UNIFIED2_IDS_EVENT_IPV6 ?  \
        offsetof(Serial_Unified2IDSEventIPv6_legacy, member) :  \
        offsetof(Serial_Unified2IDSEvent_legacy, member) \
)
#define UNIFIED_SIZE(legacy, type) ( \
    type == UNIFIED2_IDS_EVENT_IPV6 ?  \
        sizeof(Serial_Unified2IDSEventIPv6_legacy) : \
        sizeof(Serial_Unified2IDSEvent_legacy) \
)
#define UNIFIED_MEMBER_SIZE(legacy, type, member) ( \
    type == UNIFIED2_IDS_EVENT_IPV6 ?  \
        sizeof(((Serial_Unified2IDSEventIPv6_legacy *)legacy)->member) :  \
        sizeof(((Serial_Unified2IDSEvent_legacy *)legacy)->member) \
)

/* The below is from packet.h from Snort */

struct sf_timeval32
{
    uint32_t tv_sec;      /* seconds */
    uint32_t tv_usec;     /* microseconds */
};

typedef struct _Event
{
    uint32_t sig_generator;   /* which part of snort generated the alert? */
    uint32_t sig_id;          /* sig id for this generator */
    uint32_t sig_rev;         /* sig revision for this id */
    uint32_t classification;  /* event classification */
    uint32_t priority;        /* event priority */
    uint32_t event_id;        /* event ID */
    uint32_t event_reference; /* reference to other events that have gone off,
                                * such as in the case of tagged packets...
                                */
    struct sf_timeval32 ref_time;   /* reference time for the event reference */

} Event;


typedef enum _EventDataType
{
    EVENT_DATA_TYPE_BLOB = 1,
    EVENT_DATA_TYPE_MAX
} EventDataType;

//UNIFIED2_EXTRA_DATA - type 110
typedef struct _SerialUnified2ExtraData
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t type;              /* EventInfo */
    uint32_t data_type;         /*EventDataType */
    uint32_t blob_length;       /* Length of the data + sizeof(blob_length) + sizeof(data_type)*/
} SerialUnified2ExtraData;

typedef struct _Unified2ExtraDataHdr
{
    uint32_t event_type;
    uint32_t event_length;

} Unified2ExtraDataHdr;

typedef enum _EventInfoEnum
{
    EVENT_INFO_XFF_IPV4 = 1,
    EVENT_INFO_XFF_IPV6,
    EVENT_INFO_REVIEWED_BY,
    EVENT_INFO_GZIP_DATA,
    EVENT_INFO_SMTP_FILENAME,
    EVENT_INFO_SMTP_MAILFROM,
    EVENT_INFO_SMTP_RCPTTO,
    EVENT_INFO_SMTP_EMAIL_HDRS,
    EVENT_INFO_HTTP_URI,
    EVENT_INFO_HTTP_HOSTNAME,
    EVENT_INFO_IPV6_SRC,
    EVENT_INFO_IPV6_DST,
    EVENT_INFO_JSNORM_DATA
} EventInfoEnum;


#endif


