/*
  Copyright (C) 2005 Sebastien Bourdeauducq

  This file is part of PictoSniff.

  PictoSniff is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  PictoSniff is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with PictoSniff ; if not, write to the Free Software Foundation,
  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <pthread.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <net/ethernet.h>

#include "pictosniff.h"

#define RADIOTAP_OFFSET 64
#define PICTOCHAT_OFFSET 36
#define PICTOCHAT_NORMAL_PAYLOAD 160
#define PICTOCHAT_MAX_PAYLOAD 255
#define MAX_PACKETS_PER_MESSAGE 512

#define MAX_PACKET_LEN 1024

const char nintendo_mac_address_prefix[3] = { 0x00, 0x09, 0xbf };

/* Number of packets to take into account for average RSSI */
#define RSSI_PACKET_COUNT 40

struct pictochat_packet {
  uint8_t payload_size;
  uint8_t last_packet;
  uint16_t byte_counter;
  uint8_t payload_and_sequence[PICTOCHAT_MAX_PAYLOAD]; /* 16 bits sequence number, 16 bits after the end of payload */
} __attribute__((packed));

static int decode_chunk(char *im, char *raw, int *at, int chunkx, int chunky, int w)
{
  int i;
  
  for(i = 0; i < 8*8/2; i++) {
    if(chunkx * 8 + (i % 4) * 2 < w) {
      if((*(raw + *at) & 0xf) != 0) {
	*(im + 3*(chunkx*8+(i%4)*2 + w*(((i/4)+(chunky*8)))) + 0) = 0x00;
	*(im + 3*(chunkx*8+(i%4)*2 + w*(((i/4)+(chunky*8)))) + 1) = 0x00;
	*(im + 3*(chunkx*8+(i%4)*2 + w*(((i/4)+(chunky*8)))) + 2) = 0x00;
      }
      if((*(raw + *at) >> 4) != 0) {
	*(im + 3*(chunkx*8+(i%4)*2+1 + w*(((i / 4) + (chunky*8)))) + 0) = 0x00;
	*(im + 3*(chunkx*8+(i%4)*2+1 + w*(((i / 4) + (chunky*8)))) + 1) = 0x00;
	*(im + 3*(chunkx*8+(i%4)*2+1 + w*(((i / 4) + (chunky*8)))) + 2) = 0x00;
      }
    }
    (*at)++;
  }
  return 1;
}

static int display_message(const struct pictochat_packet *packets, unsigned int packet_count)
{
  unsigned int i, j, k;
  unsigned int blocks, width, height;
  char *im;
  char *raw;
  
  /* Count unique packets */
  j = 1;
  for(i=1;i<packet_count;i++) {
    if((packets+i)->byte_counter != (packets+i-1)->byte_counter) j++;
  }
  
  blocks = ((j-1)/12);
  width = 220;
  height = blocks*16;
  if(blocks <= 0) return 0;
  im = malloc(width*height*3);
  if(im == NULL) return 0;
  memset(im, 0xff, width*height*3);
  raw = malloc((j+1)*PICTOCHAT_NORMAL_PAYLOAD);
  if(raw == NULL) return 0;
  j = 0;
  memcpy(raw, packets[0].payload_and_sequence, PICTOCHAT_NORMAL_PAYLOAD);
  for(i=1;i<packet_count;i++) {
    if((packets+i)->byte_counter != (packets+i-1)->byte_counter) {
      j++;
      memcpy(raw+j*PICTOCHAT_NORMAL_PAYLOAD, &((packets+i)->payload_and_sequence[0]), PICTOCHAT_NORMAL_PAYLOAD);
    }
  }
  memset(raw+(j+1)*PICTOCHAT_NORMAL_PAYLOAD, 0, PICTOCHAT_NORMAL_PAYLOAD);
  
  k = 166;
  for(j=0;j<blocks*2;j++) {
    for(i=0;i<224/8;i++) decode_chunk(im, raw, &k, i, j, width);
    k += 4*8*4;
  }
  
  free(raw);
  add_message(im, width, height);
  return 1;
}

static pcap_t *pcap_source;
static int terminate_thread = 0;

static int rssi_levels[RSSI_PACKET_COUNT];
static int rssi_ptr = 0;

static struct pictochat_packet *packets;

static void *sniff_thread(void *arg)
{
  const unsigned char *packet_data;
  struct pcap_pkthdr packet_header;
  int message_started;
  unsigned int i, j, k;
  unsigned int former_byte_counter;
  int seen_packets;
  
  message_started = 0;
  former_byte_counter = 0;
  seen_packets = 0;
  i = 0;
  while(1) {
    packet_data = pcap_next(pcap_source, &packet_header);
    if(packet_data == NULL) {
      if(terminate_thread) return NULL;
      if((!seen_packets) && message_started) {
        display_message(&packets[0], i-1);
        message_started = 0;
        former_byte_counter = 0;
        seen_packets = 0;
        i = 0;
      }
      seen_packets = 0;
      continue;
    }
    /* Check for Nintendo DS MAC address */
    if(memcmp(packet_data+RADIOTAP_OFFSET+10, &nintendo_mac_address_prefix, sizeof(nintendo_mac_address_prefix)) == 0) {
      /* We always update the RSSI in this case, taking into account NDS beacons */
      rssi_levels[rssi_ptr] = *(packet_data+13);
      rssi_ptr++;
      if(rssi_ptr == RSSI_PACKET_COUNT) {
        j = 0;
        for(k=0;k<RSSI_PACKET_COUNT;k++) j += rssi_levels[k];
        update_rssi(j/RSSI_PACKET_COUNT);
        rssi_ptr = 0;
      }
      /* Check for PictoChat message packet length */
      if(packet_header.len == 270) {
        /* Check for PictoChat message payload length (inside Nintendo DS protocol) */
        /* there muse be a more reliable way to detect PictoChat messages ... */
        if(*(packet_data+RADIOTAP_OFFSET+PICTOCHAT_OFFSET) == PICTOCHAT_NORMAL_PAYLOAD) {
          seen_packets = 1;
          if(!message_started) {
            message_started = 1;
            i = 0;
          } else {
            i++;
          }
          if(i == MAX_PACKETS_PER_MESSAGE) {
            fputs("too many packets in message\n", stderr);
            return 0;
          }
          memset(&packets[i], 0, sizeof(struct pictochat_packet));
          memcpy(&packets[i], packet_data+RADIOTAP_OFFSET+PICTOCHAT_OFFSET, sizeof(struct pictochat_packet)-PICTOCHAT_MAX_PAYLOAD+PICTOCHAT_NORMAL_PAYLOAD+4);
          if(packets[i].byte_counter < former_byte_counter) {
            message_started = 1;
            display_message(&packets[0], i-1);
            memcpy(&packets[0], packet_data+RADIOTAP_OFFSET+PICTOCHAT_OFFSET, sizeof(struct pictochat_packet)-PICTOCHAT_MAX_PAYLOAD+PICTOCHAT_NORMAL_PAYLOAD+4);
            i = 0;
          }
          former_byte_counter = packets[i].byte_counter;
        }
      }
    }
  }
  return NULL;
}

static pthread_t threadid;

int start_sniffing(const char *iface)
{
  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  int *id;

  pcap_source = pcap_open_live(iface, MAX_PACKET_LEN, 1, 100, &pcap_errbuf[0]);
  if(pcap_source == NULL) {
    fprintf(stderr, "pcap_open_live() failed : %s\n", &pcap_errbuf[0]);
    return 0;
  }
  pcap_list_datalinks(pcap_source, &id);
  while(*id != 0) {
    if(strcmp(pcap_datalink_val_to_name(*id), "IEEE802_11_RADIO") == 0) break;
    id++;
  }
  if(*id == 0) {
    fputs("Radiotap not available\n", stderr);
    return 0;
  }
  packets = malloc((MAX_PACKETS_PER_MESSAGE+1)*sizeof(*packets));
  if(packets == NULL) {
    perror("malloc");
    return 0;
  }
  pcap_set_datalink(pcap_source, *id);
  if(pthread_create(&threadid, NULL, sniff_thread, NULL) != 0) {
    perror("pthread_create");
    return 0;
  }
  return 1;
}

int end_sniffing()
{
  terminate_thread = 1;
  pthread_join(threadid, NULL);
  pcap_close(pcap_source);
  free(packets);
  return 1;
}
