/* ulogd_HTTPSNIFF.c, Version $Revision$
 *
 * ulogd logging interpreter for HTTP plaintext URLs.
 * based on ulogd_PWSNIFF.c
 *
 * (C) 2017 by Jean Weisbuch <jean@phpnet.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ulogd/ulogd.h>

// If ONLY_LOG_HTTPSNIFF is defined, only packets having HOST and/or URI informations will be sent to output
#define ONLY_LOG_HTTPSNIFF

enum input_keys {
	KEY_RAW_PKT,
};

enum http_methods {
	UNKNOWN_METHOD,
	GET_METHOD,
	POST_METHOD,
};

static u_int16_t httpsniff_ports[] = {
	80,
	/* feel free to include any other ports here, provided that their
	 * host/uri syntax is the same */
};

static unsigned char *_get_next_blank(unsigned char* begp, unsigned char *endp)
{
	unsigned char *ptr;

	for (ptr = begp; ptr < endp; ptr++) {
		if (*ptr == ' ' || *ptr == '\n' || *ptr == '\r')
//		if (*ptr == ' ' || *ptr == '\n' || *ptr == '\r' || *ptr == '\0')
			return ptr-1;
if ( *ptr == '\0') {
	ulogd_log(ULOGD_NOTICE, "httpsniff NULL !!!");
	return ptr-1;
}
	}
	return NULL;
}

static int interp_httpsniff(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
//	struct iphdr *iph;
	struct iphdr *iph = ikey_get_ptr(&pi->input.keys[KEY_RAW_PKT]);
	void *protoh;
	struct tcphdr *tcph;
	unsigned int tcplen;
	unsigned char  *ptr, *begp, *uri_begp, *endp, *uri_endp;
	int len, uri_len, cont = 0;
	unsigned int i;

	u_int8_t http_method = UNKNOWN_METHOD;

	struct ulogd_key *inp = pi->input.keys;
	if(!pp_is_valid(inp, KEY_RAW_PKT)) {
		ulogd_log(ULOGD_ERROR, "httpsniff invalid input key for KEY_RAW_PKT : %d", inp[KEY_RAW_PKT]);
		return ULOGD_IRET_STOP;
}

//	iph = (struct iphdr *) pi->input.keys[0].u.value.ptr;
//	iph = (struct iphdr *) inp[0].u.value.ptr;
	protoh = (u_int32_t *)iph + iph->ihl;
	tcph = protoh;
	tcplen = ntohs(iph->tot_len) - iph->ihl * 4;

	len = uri_len = 0;
	begp = uri_begp = NULL;

	if (iph->protocol != IPPROTO_TCP) {
		ulogd_log(ULOGD_DEBUG, "httpsniff packet is not TCP (%d)", iph->protocol);
		return ULOGD_IRET_STOP;
	}

	// Loop on each ports listed on httpsniff_ports and set cont=1 if the dstport is matching
	for (i = 0; i < ARRAY_SIZE(httpsniff_ports); i++)
	{
		if (ntohs(tcph->dest) == httpsniff_ports[i]) {
			cont = 1;
			break;
		}
	}
	if (!cont) {
		ulogd_log(ULOGD_DEBUG, "httpsniff packet dstport (%d) is not listed in httpsniff_ports", tcph->dest);
		return ULOGD_IRET_STOP;
	}

	for (ptr = (unsigned char *) tcph + sizeof(struct tcphdr); ptr < (unsigned char *) tcph + tcplen; ptr++) {
		if (!strncasecmp((char *)ptr, "HOST: ", 6)) {
			begp = ptr+6;
			endp = _get_next_blank(begp, (unsigned char *)tcph + tcplen);
			if (endp)
				len = endp - begp + 1;
		} else if (!strncasecmp((char *)ptr, "GET ", 4)) {
			uri_begp = ptr+4;
			uri_endp = _get_next_blank(uri_begp, (unsigned char *)tcph + tcplen);
			if (uri_endp)
				uri_len = uri_endp - uri_begp + 1;
			http_method = GET_METHOD;
		} else if (!strncasecmp((char *)ptr, "POST ", 5)) {
			uri_begp = ptr+5;
			uri_endp = _get_next_blank(uri_begp, (unsigned char *)tcph + tcplen);
			if (uri_endp)
				uri_len = uri_endp - uri_begp + 1;
			http_method = POST_METHOD;
		}
		if(len && uri_len) {
			// We already have all the informations we need, no need to continue to parse the packet
			break;
		}
	}

	if(!len && !uri_len) {
		// There was no "HOST:" or "GET/POST" on this packet
#ifdef ONLY_LOG_HTTPSNIFF
		return ULOGD_IRET_STOP;
#else
		return ULOGD_IRET_OK;
#endif
	}

	if (len) {
		char *ptr;
		ptr = (char *) malloc(len+1);
		if (!ptr) {
			ulogd_log(ULOGD_ERROR, "httpsniff !ptr len");
			return ULOGD_IRET_ERR;
		}
		strncpy(ptr, (char *)begp, len);
		ptr[len] = '\0';
		okey_set_ptr(&ret[0], ptr);
	}
	if (uri_len) {
		char *ptr;
		ptr = (char *) malloc(uri_len+1);
		if (!ptr) {
			ulogd_log(ULOGD_ERROR, "httpsniff !ptr uri_len");
			return ULOGD_IRET_ERR;
		}
		strncpy(ptr, (char *)uri_begp, uri_len);
		ptr[uri_len] = '\0';
		okey_set_ptr(&ret[1], ptr);
	}

	if(http_method) {
		okey_set_u8(&ret[2], http_method);
	}
	ulogd_log(ULOGD_DEBUG, "----> httpsniff detected, tcplen=%d, iphtotlen=%d, ihl=%d, host=%s, uri=%s, method=%d\n", tcplen, ntohs(iph->tot_len), iph->ihl, ret[0].u.value.ptr, ret[1].u.value.ptr, http_method);
	return ULOGD_IRET_OK;
}

static struct ulogd_key httpsniff_inp[] = {
	[KEY_RAW_PKT] = {
		.name 	= "raw.pkt",
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
	},
};

static struct ulogd_key httpsniff_outp[] = {
	{
		.name	= "httpsniff.host",
		.type	= ULOGD_RET_STRING,
	},
	{
		.name 	= "httpsniff.uri",
		.type	= ULOGD_RET_STRING,
	},
	{
		.name 	= "httpsniff.method",
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
	},
};

static struct ulogd_plugin httpsniff_plugin = {
	.name	= "HTTPSNIFF",
	.input	= {
		.keys = httpsniff_inp,
		.num_keys = ARRAY_SIZE(httpsniff_inp),
		.type = ULOGD_DTYPE_PACKET,
	},
	.output	= {
		.keys = httpsniff_outp,
		.num_keys = ARRAY_SIZE(httpsniff_outp),
		.type = ULOGD_DTYPE_PACKET,
	},
	.interp = &interp_httpsniff,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void)
{
	ulogd_register_plugin(&httpsniff_plugin);
}
