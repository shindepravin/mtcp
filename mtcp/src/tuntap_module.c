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

#include <stdbool.h>
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


/*----------------------------------------------------------------------------*/
#define dprintf(arg...) do { printf("TUNTAP:%s:%s:%d: ", \
                    __FILE__ , __func__, __LINE__); \
                    printf(arg);\
            } while (0)


//#define TUNTAP_DEBUG 1

#if TUNTAP_DEBUG
#define DEBUGPRINT(arg...)      dprintf(arg)
#else
#define DEBUGPRINT(arg...)      ((void)0)
#endif // TUNTAP_DEBUG
/*----------------------------------------------------------------------------*/


typedef uint16_t pktoff_t;

#define MAX_QUEUE_SIZE               (64)

/*----------------------------------------------------------------------------*/
// packet buffer and length
struct my_pkt {
    uint8_t     buf[MAX_PKT_SIZE];    // packet buffer
    int         valid_data_length;      // valid data length
};

typedef  struct my_pkt  my_pkt_t;

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* Implementation of a stupid queue */
struct myq {
	my_pkt_t    pkt_list[MAX_QUEUE_SIZE];  // packet list
        int         len;                       // allocated pkts
};
typedef  struct myq myq_t;


static bool myq_is_empty(struct myq *q)
{
    if (q->len == 0) return true;
    return false;
}

static bool myq_is_full(struct myq *q)
{
    if (q->len == MAX_QUEUE_SIZE) return true;
    return false;
}
static int myq_len(struct myq *q)
{
    return q->len;
}

static bool myq_remove_elems(struct myq *q, int to_remove)
{
    if (q->len != to_remove) {
        dprintf("ERROR: not all pkts processed! (len: %d != processed: %d)\n",
                q->len, to_remove);
        exit(EXIT_FAILURE);
        return false;
    }
    q->len = 0;
    return true;
}


/* add an element to the queue  */
static
my_pkt_t *myq_add_elem(struct myq *q)
{
    if (myq_is_full(q)) {
        dprintf("Queue full, so adding element failed\n");
        return NULL;
    }
    my_pkt_t *pktb = &q->pkt_list[q->len];
    ++q->len;
    pktb->valid_data_length = 0;
    return pktb;
}

static
my_pkt_t *myq_get_perticular_elem(struct myq *q, int pos)
{

    if (pos >= q->len) {
        return NULL;
    }
    return &q->pkt_list[pos];
}


/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

struct tap_handler {
	int tun_fd;
	int ctl_fd;
	char name[IFNAMSIZ];
        struct myq rxq;
        struct myq txq;
	int    rmlist[MAX_QUEUE_SIZE];  // list of packets which can be reused
	int    rmlist_head;             // list of packets which can be reused
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

        memset(tap, 0, sizeof(struct tap_handler));

        tap_open(tap, name);
	return tap;
}

static void *tap_dev_list[MAX_DEVICES];
static int tap_devs_created = 0;

void *init_tap_network(char *ifname, char *ipaddr, char *ipmask)
{
    struct tap_handler *tap = NULL;
    tap = tap_create(ifname);
    tap_up(tap);
    tap_set_ip(tap, ipaddr);
    tap_set_mask(tap, ipmask);

    if (tap_devs_created >= MAX_DEVICES) {
        dprintf("ERROR: There are already %d deviced created\n",
                tap_devs_created);
        exit(EXIT_FAILURE);
        return NULL;
    }

    // saving the device info in the list of devices
    tap_dev_list[tap_devs_created] = tap;
    ++tap_devs_created;
    return tap;
}


/*----------------------------------------------------------------------------*/


/*----------------------------------------------------------------------------*/
void
tuntap_init_handle(struct mtcp_thread_context *ctxt)
{
	DEBUGPRINT("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
        if (tap_devs_created == 0) {
	    dprintf("ERROR: No tuntap devices initialized yet\n");
            exit(EXIT_FAILURE);
        }
	ctxt->io_private_context = tap_dev_list;
}

/*----------------------------------------------------------------------------*/
int
tuntap_link_devices(struct mtcp_thread_context *ctxt)
{
	/* linking takes place during mtcp_init() */

	DEBUGPRINT("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
	return 0;
}
/*----------------------------------------------------------------------------*/
// function to get the device associated with nif
static struct tap_handler *
get_proper_dev(struct mtcp_thread_context *ctxt, int nif)
{
        if(nif >= tap_devs_created) {
            dprintf("ERROR: Interface %d requested, but we only have %d tap devs\n",
                    nif, tap_devs_created);
            exit(EXIT_FAILURE);
        }

        if (ctxt->io_private_context == NULL) {
            dprintf("ERROR: %s:%s:%d => tap handler list is not set\n",
                    __FILE__, __FUNCTION__, __LINE__ );
            exit(EXIT_FAILURE);
        }

        struct tap_handler *tap = (struct tap_handler *)tap_dev_list[nif];
        if (tap == NULL) {
            dprintf("ERROR: %s:%s:%d => tap handler for nif %d not set\n",
                    __FILE__, __FUNCTION__, __LINE__ , nif);
            exit(EXIT_FAILURE);
        }
        return tap;
}

/*----------------------------------------------------------------------------*/
void
tuntap_release_pkt(struct mtcp_thread_context *ctxt, int ifidx,
        unsigned char *pkt_data,
        int len)
{
        //struct tap_handler *tap = get_proper_dev(ctxt, ifidx);
	/*
	 * do nothing over here - memory reclamation
	 * will take place in tuntap_recv_pkts
	 */
	DEBUGPRINT("Releasing a packet of len %d\n", len);
}

/*----------------------------------------------------------------------------*/
int
tuntap_send_pkts(struct mtcp_thread_context *ctxt, int nif)
{
        //DEBUGPRINT(" nif = %d\n", nif);
        struct tap_handler *tap = get_proper_dev(ctxt, nif);
	int sent;
	int i;

        if (myq_is_empty(&tap->txq)) {
            return 0;
        }

        sent = myq_len(&tap->txq);

        // for each prepared packet, send it out
        for (i = 0; i < sent; ++i)
        {
            // get the packet
            my_pkt_t *pkt = myq_get_perticular_elem(&tap->txq, i);
            // Find out lenght of valid packet data
            // send it out
            int ret = tap_write(tap, pkt->buf, pkt->valid_data_length);
            if (ret != pkt->valid_data_length) {
                perror("tap write: ");
                dprintf("sending over tap dev failed.  "
                        "only %d bytes send instead of %d.  (nif = %d)\n",
                        ret, pkt->valid_data_length, nif);
                exit(EXIT_FAILURE);
            }
        } // end for: each buffered packet

        // reset the queue length to reflect new reality
        myq_remove_elems(&tap->txq, sent);
	return sent;
}

/*----------------------------------------------------------------------------*/
uint8_t *
tuntap_get_wptr(struct mtcp_thread_context *ctxt, int nif, uint16_t pktsize)
{
	DEBUGPRINT("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
        struct tap_handler *tap = get_proper_dev(ctxt, nif);

        if (pktsize >= MAX_PKT_SIZE) {
            exit(EXIT_FAILURE);
            return NULL;
        }

        if (myq_is_full(&tap->txq)) {
            dprintf("no buffers left for allocation\n");
            return NULL;
        }

        /* we need empty buffer to write new packet, so we use this queue
         * to add new packets which will be prepared "soon" */
        my_pkt_t *pkt_buf = myq_add_elem(&tap->txq);
        pkt_buf->valid_data_length = pktsize;
	return (uint8_t *)pkt_buf->buf;
}

static int pkt_count = 0;
/*----------------------------------------------------------------------------*/
int32_t
tuntap_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx)
{
        int ret = 0;
        int i = 0;
        struct tap_handler *tap = get_proper_dev(ctxt, ifidx);
	//DEBUGPRINT("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );

        // reclaim all the buffers which are already processed by client
        for (i = 0; i < tap->rmlist_head; ++i) {
            // mark the buffer reclaimed
            //      do I need to do anything here?
            //      I guess not.
        }
        myq_remove_elems(&tap->rxq, tap->rmlist_head);

        // mark reclaimed list (rmlist) processed
        tap->rmlist_head = 0;

        // make sure that there is a space to receive a new packet
        if (myq_is_full(&tap->rxq)) {
            dprintf("no buffers left for allocation\n");
            return ret;
        }

        // get a packet buffer where I can receive the next packet
        my_pkt_t *pkt_buf = myq_add_elem(&tap->rxq);

        // Can I block reading here?
        //      assuming  blocking for time being
        //      based on quick glance on dpdk_module.c code

        // read the packet from the device
        pkt_buf->valid_data_length = tap_read(tap, pkt_buf->buf, MAX_PKT_SIZE);
        ++ret;
        ++pkt_count;
	DEBUGPRINT("[pktid:%d]: pkt of size %d received\n",
                pkt_count,
                pkt_buf->valid_data_length);

        // TODO: check if there are more packets,
        //          and get them if they are there
        //          use select for this.  If it returns without any new packets
        //          then return, otherwise read all the packets
        //  Currently, only one packet will be received in each call

        return ret;
}
/*----------------------------------------------------------------------------*/
uint8_t *
tuntap_get_rptr(struct mtcp_thread_context *ctxt, int ifidx, int index,
        uint16_t *len)
{

        uint8_t *pktbuf = NULL;
	//DEBUGPRINT("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
        struct tap_handler *tap = get_proper_dev(ctxt, ifidx);

        int rxq_valid_pkts_count = myq_len(&tap->rxq);
        // make sure that the index is valid
        if (index < 0 || index >= rxq_valid_pkts_count) {
            // invalid index
            dprintf("ERROR: Given index value %d is invalid (rxq len = %d)\n",
                    index, rxq_valid_pkts_count);
            exit(EXIT_FAILURE);
            return NULL;
        }

        // Prepare the pointer to actual data which will be returned
        my_pkt_t *selected_pkt = myq_get_perticular_elem(&tap->rxq, index);
        pktbuf = selected_pkt->buf;

        // set the length of the packet
        *len = selected_pkt->valid_data_length;

        // add this index to the list of buffers which are to be reused
        // Make sure that there is a space in rmlist to add this packet buff
        //      for future reuse
        // Should upper limit be MAX_QUEUE_SIZE or valid RX elems?
        //          I am going with valid RX elems for time being
        if(tap->rmlist_head >= rxq_valid_pkts_count) {
            dprintf("ERROR: Too many pkt buffers are still in read-release"
                    " queue (rmlist_head = %d >= valid packets count = %d)\n",
                    tap->rmlist_head, rxq_valid_pkts_count);
            exit(EXIT_FAILURE);
            return NULL;
        }

        tap->rmlist[tap->rmlist_head] = index;
        ++tap->rmlist_head;

	return pktbuf;
}
/*----------------------------------------------------------------------------*/
int32_t
tuntap_select(struct mtcp_thread_context *ctxt)
{
    	//DEBUGPRINT("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
        int ret = 0;

	return ret;
}
/*----------------------------------------------------------------------------*/
void
tuntap_destroy_handle(struct mtcp_thread_context *ctxt)
{
	DEBUGPRINT("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
}

/*----------------------------------------------------------------------------*/
void
tuntap_load_module(void)
{
	DEBUGPRINT("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__ );
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
