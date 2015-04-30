/* for io_module_func def'ns */
#include "io_module.h"
#ifndef DISABLE_TUNTAP
/* for mtcp related def'ns */
#include "mtcp.h"
/* for errno */
#include <errno.h>
/* for logging */
#include "debug.h"
/* for num_devices_* */
#include "config.h"



/*----------------------------------------------------------------------------*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>

#define TUNDEV "/dev/net/tun"

typedef uint16_t pktoff_t;
typedef uint16_t portno_t;
typedef void* device_t;

struct tap_handler {
	int tun_fd;
	int ctl_fd;
	char name[IFNAMSIZ];
};

static void
tap_open(struct tap_handler *tap, char *name)
{
	struct ifreq ifr = {{{0}}};

	if (name)
		strncpy(tap->name, name, sizeof(tap->name));
	strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	tap->tun_fd = open(TUNDEV, O_RDWR);
	if (tap->tun_fd < 0)
		err(1, TUNDEV);

	if (ioctl(tap->tun_fd, TUNSETIFF, &ifr) < 0)
		err(1, "TUNSETIFF");

	if ((tap->ctl_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
		err(1, "socket");
}

static void
tap_up(struct tap_handler *tap)
{
	struct ifreq ifr = {{{0}}};

	strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name));
	if (ioctl(tap->ctl_fd, SIOCGIFFLAGS, &ifr) < 0)
		err(1, "ioctl: SIOCGIFFLAGS");

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

	if (ioctl(tap->ctl_fd, SIOCSIFFLAGS, &ifr) < 0)
		err(1, "ioctl: SIOCSIFFLAGS");
}

static int
tap_set_addr(struct tap_handler *tap, int cmd, const char *addr_str)
{
	struct ifreq ifr = {{{0}}};
	struct sockaddr_in addr;

	strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name));

	addr.sin_family = AF_INET;
	if (!inet_aton(addr_str, &addr.sin_addr))
		err(1, "inet_aton: %s\n", addr_str);
	memcpy(&ifr.ifr_addr, &addr, sizeof(addr));

	return ioctl(tap->ctl_fd, cmd, &ifr);
}

static void
tap_set_ip(struct tap_handler *tap, const char *ip)
{
	if (tap_set_addr(tap, SIOCSIFADDR, ip) < 0)
		err(1, "SIOCGIFFLAGS: %s", ip);
}

void
tap_set_mask(struct tap_handler *tap, const char *mask)
{
	if (tap_set_addr(tap, SIOCSIFNETMASK, mask) < 0)
		err(1, "SIOCSIFNETMASK: %s", mask);
}

static ssize_t
tap_read(struct tap_handler *tap, uint8_t *buff, pktoff_t len)
{
	ssize_t ret;

	/*
	struct tun_pi *pi;
	pi = (struct tun_pi *)buff;
	pi->flags = 0;
	pi->proto = 666;
	*/

	// we will want to handle some (e.g., EAGAIN), but for now just die
	if ((ret = read(tap->tun_fd, buff, (len))) < 0)
		err(1, "read failed");
	else if (ret == 0)    // ditto for EOF
		err(1, "read returned 0");

	return ret;
}

static int
tap_write(struct tap_handler *tap, uint8_t *buff, size_t len)
{
	ssize_t ret;

	if ((ret = write(tap->tun_fd, buff, len)) < 0) {
		err(1, "write failed");
                return ret;
        }
	else if (ret < len) {
		err(1, "short write");
                return -1;
        }
        return ret;
}

struct tap_handler *
tap_create(char *name)
{
	struct tap_handler *tap;

	tap = malloc(sizeof(*tap));
	if (!tap)
		err(1, "malloc");

	tap_open(tap, name);
	return tap;
}

static
struct tap_handler *init_tap_network(char *ifname)
{
    char *ipaddr = "192.168.123.100";
    char *ipmask = "255.255.255.0";
    struct tap_handler *tap = NULL;
    tap = tap_create(ifname);
    tap_up(tap);
    tap_set_ip(tap, ipaddr);
    tap_set_mask(tap, ipmask);
    return tap;
}

#define CONFIG_LOCAL_MAC_TUNTAP    0xf86954221b00ULL   // 00:1b:22:54:69:f8
#define CONFIG_LOCAL_IP_TUNTAP    0xc0a87b01          // 192.168.123.1

static
uint64_t tuntap_mac_read(device_t ttd) {
    return (CONFIG_LOCAL_MAC_TUNTAP);
}

static
uint32_t tuntap_ip_read(device_t ttd) {
    return (CONFIG_LOCAL_IP_TUNTAP);
}

static
void *init_tap_wrapper(char *arg)
{
    return ((void *)init_tap_network("dragonet0"));
}

static
pktoff_t tap_rx_wrapper(device_t dev, uint8_t *data, pktoff_t len)
{
    struct tap_handler *tap = (struct tap_handler *)dev;
    return ((pktoff_t)tap_read(tap, data, len));
}

static
int tap_tx_wrapper(device_t dev, uint8_t *data, pktoff_t len)
{
    struct tap_handler *tap = (struct tap_handler *)dev;
    return (tap_write(tap, data, len));
}


/*----------------------------------------------------------------------------*/


/*----------------------------------------------------------------------------*/


static void *tap_dev;
/*----------------------------------------------------------------------------*/
void
tuntap_init_handle(struct mtcp_thread_context *ctxt)
{

	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
        tap_dev = ((void *)init_tap_network("dragonet0"));
}

/*----------------------------------------------------------------------------*/
int
tuntap_link_devices(struct mtcp_thread_context *ctxt)
{
	/* linking takes place during mtcp_init() */

	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
	return 0;
}
/*----------------------------------------------------------------------------*/
void
tuntap_release_pkt(struct mtcp_thread_context *ctxt, int ifidx, unsigned char *pkt_data, int len)
{
	/*
	 * do nothing over here - memory reclamation
	 * will take place in tuntap_recv_pkts
	 */
	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
}
/*----------------------------------------------------------------------------*/
int
tuntap_send_pkts(struct mtcp_thread_context *ctxt, int nif)
{
	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
	int ret;
	ret = 0;
	return ret;
}
/*----------------------------------------------------------------------------*/
uint8_t *
tuntap_get_wptr(struct mtcp_thread_context *ctxt, int nif, uint16_t pktsize)
{
	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
	uint8_t *ptr;
        ptr = NULL;
	return (uint8_t *)ptr;
}
/*----------------------------------------------------------------------------*/
static inline void
free_pkts(struct rte_mbuf **mtable, unsigned len)
{
	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
}
/*----------------------------------------------------------------------------*/
int32_t
tuntap_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx)
{
	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
	int ret;
	return ret;
}
/*----------------------------------------------------------------------------*/
uint8_t *
tuntap_get_rptr(struct mtcp_thread_context *ctxt, int ifidx, int index, uint16_t *len)
{
	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
	uint8_t *pktbuf;
	pktbuf = NULL;
	return pktbuf;
}
/*----------------------------------------------------------------------------*/
int32_t
tuntap_select(struct mtcp_thread_context *ctxt)
{
    //	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );

	return 0;
}
/*----------------------------------------------------------------------------*/
void
tuntap_destroy_handle(struct mtcp_thread_context *ctxt)
{
	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
}

/*----------------------------------------------------------------------------*/
void
tuntap_load_module(void)
{
	printf("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
}
/*----------------------------------------------------------------------------*/
io_module_func tuntap_module_func = {
	.load_module		   = tuntap_load_module,
	.init_handle		   = tuntap_init_handle,
	.link_devices		   = tuntap_link_devices,
	.release_pkt		   = tuntap_release_pkt,
	.send_pkts		   = tuntap_send_pkts,
	.get_wptr   		   = tuntap_get_wptr,
	.recv_pkts		   = tuntap_recv_pkts,
	.get_rptr	   	   = tuntap_get_rptr,
	.select			   = tuntap_select,
	.destroy_handle		   = tuntap_destroy_handle
};
/*----------------------------------------------------------------------------*/
#else
io_module_func tuntap_module_func = {
	.load_module		   = NULL,
	.init_handle		   = NULL,
	.link_devices		   = NULL,
	.release_pkt		   = NULL,
	.send_pkts		   = NULL,
	.get_wptr   		   = NULL,
	.recv_pkts		   = NULL,
	.get_rptr	   	   = NULL,
	.select			   = NULL,
	.destroy_handle		   = NULL
};
/*----------------------------------------------------------------------------*/
#endif /* !DISABLE_TUNTAP */
