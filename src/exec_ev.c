#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <ev.h>
#include <sutil.h>
#include <cameo_ev.h>

#ifndef cprintf
#define cprintf(fmt, args...) do { \
        FILE *cfp = fopen("/dev/console", "w"); \
        if (cfp) { \
                fprintf(cfp, fmt, ## args); \
                fclose(cfp); \
        } \
} while (0)
#endif

static void send_event(int destPID, Event_ptr_t ev_reply)
{
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_nl dest_addr;
	int sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
	int max_len = MAX_EVENT_LEN;

	if (sock_fd < 0) {
		cprintf("%s[%d]:Socket create fail\n", __func__, __LINE__);
		return;
	}

	// set dest socket
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = destPID;
	dest_addr.nl_groups = 0; // unicast

	// construct nl header
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(max_len));
	if (nlh == NULL)
		goto exit;

	memset(nlh, 0, NLMSG_SPACE(max_len));
	nlh->nlmsg_len = NLMSG_SPACE(max_len);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	// set a event message to send
	memcpy(NLMSG_DATA(nlh), ev_reply, sizeof(Event_t));

	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(sock_fd, &msg, 0);

	free(nlh);

exit:
	close(sock_fd);
	return;
}

enum UPDATE_WIFI_LED_STATUS_LIST {
	CLIENT_CONNECT_2G =1,
	CLIENT_CONNECT_5G ,
	NO_CLIENT_CONNECT_2G ,
	NO_CLIENT_CONNECT_5G ,
	UPDATE_2G_RSSI ,
	UPDATE_5G_RSSI ,
	NO_LINK_STA_2G ,
	NO_LINK_STA_5G ,

	DO_NOTHING =0,
};

void update_wifi_led(Event_ptr_t ev_req)
{
	unsigned int status=0;
	int level, channel, size;
	char *pch;

	//split payload
	pch = strtok(ev_req->payload, ",");
	level = atoi(pch);
	pch = strtok(NULL, ",");
	channel = atoi(pch);
	pch = strtok(NULL, ",");
	size = atoi(pch);

	if (size < 0 && uci_match("cameo.system.rt_mode", "repeater")) {
		//when apcli connected or apcli disconnect
		if (channel > 14) {
			if (level == -1)
				status = NO_LINK_STA_5G;
			else
				status = UPDATE_5G_RSSI;
		} else {
			if (level == -1)
				status = NO_LINK_STA_2G;
			else
				status = UPDATE_2G_RSSI;
		}
	} else if (size >= 0 && uci_match("cameo.system.rt_mode", "repeater") != 1) {
		//when first client connected or last client disconnect
		if (channel > 14) {
			if (size == 1)
				status = CLIENT_CONNECT_5G;
			else if (size == 0)
				status = NO_CLIENT_CONNECT_5G;
		} else {
			if (size == 1)
				status = CLIENT_CONNECT_2G;
			else if (size == 0)
				status = NO_CLIENT_CONNECT_2G;
		}
	}

	//cprintf("xxx update_wifi_led status: %d\n", status);

	switch (status) {
		case CLIENT_CONNECT_2G:
			system("/sbin/ledctrl 2.4g-white blink");
			break;
		case CLIENT_CONNECT_5G:
			system("/sbin/ledctrl 5g-white blink");
			break;
		case NO_CLIENT_CONNECT_2G:
			system("/sbin/ledctrl 2.4g-white on");
			break;
		case NO_CLIENT_CONNECT_5G:
			system("/sbin/ledctrl 5g-white on");
			break;
		case UPDATE_2G_RSSI:
			if ((uci_match("wireless_router.wlan0.easymesh", "1"))&&(uci_match("wireless.wlan0.rep_mode", "normal")))
			{
				system("/sbin/ledctrl 2.4g-amber off ");
				break;
			}

			if (level == 2)
				system("/sbin/ledctrl 2.4g-amber on ");
			else if (level == 1)
				system("/sbin/ledctrl 2.4g-green on ");
			else if (level == 0)
				system("/sbin/ledctrl 2.4g-red on ");
			break;
		case UPDATE_5G_RSSI:
			if ((uci_match("wireless_router.wlan0.easymesh", "1"))&&(uci_match("wireless.wlan0.rep_mode", "normal")))
			{
				system("/sbin/ledctrl 5g-amber off ");
				break;
			}
			if (level == 2)
				system("/sbin/ledctrl 5g-amber on ");
			else if (level == 1)
				system("/sbin/ledctrl 5g-green on ");
			else if (level == 0)
				system("/sbin/ledctrl 5g-red on ");
			break;
		case NO_LINK_STA_2G:
			system("/sbin/ledctrl 2.4g-amber off ");
			if (access("/var/run/sta_daemon.pid", F_OK) != 0 &&
				uci_match("wireless_repeater.wlan0.rep_mode", "normal"))
				system("/usr/bin/sta_monitor.sh");
			break;
		case NO_LINK_STA_5G:
			system("/sbin/ledctrl 5g-amber off ");
			if (access("/var/run/sta_daemon.pid", F_OK) != 0 &&
				uci_match("wireless_repeater.wlan0.rep_mode", "normal"))
				system("/usr/bin/sta_monitor.sh");
			break;
		case DO_NOTHING:
			break;
	}
}

void exec_event(int destPID, Event_ptr_t ev_req)
{
	Event_t ev_reply;

	switch (ev_req->id) {
	case UPDATE_WIFI_LED:
		if (access("/tmp/ssidcopy_starting", F_OK) != 0 && access("/tmp/done", F_OK) == 0)
			update_wifi_led(ev_req);
		break;
	case LINK_WAN_ST:
		if (strncmp(ev_req->payload, "0", 1) == 0) {
			if (uci_match("cameo.system.rt_mode", "router")) {
				uci_set_option("cameo.wan.cable_connect", "0");
				if (!uci_match("network.wan.proto", "static")) {
					system("ubus call network.interface.wan6 down");
					system("ubus call network.interface.fake down");
				}
			}
			if (uci_match("network.wan.proto", "dhcp"))
				system("killall -SIGUSR2 udhcpc");
			cprintf("clink: WAN down.\n");
		} else if (strncmp(ev_req->payload, "1", 1) == 0) {
			if (uci_match("cameo.system.rt_mode", "router")) {
				uci_set_option("cameo.wan.cable_connect", "1");
				if (!uci_match("network.wan.proto", "static")) {
					system("ubus call network.interface.wan6 up");
					system("ubus call network.interface.fake up");
				}
			}
			if ((uci_match("cameo.system.rt_mode", "ap") && uci_match("network.lan.proto", "dhcp")) ||
				uci_match("network.wan.proto", "dhcp"))
				system("killall -SIGUSR1 udhcpc");
			cprintf("clink: WAN up.\n");
		} else if (strncmp(ev_req->payload, "2", 1) == 0) {
			if (uci_match("cameo.system.rt_mode", "repeater"))
				// support renew dhcp when mesh repeater connect to normal router with ethernet
				system("touch /tmp/eth_connect");
		} else
			cprintf("clink: LINK_WAN unknow type\n");
		break;
	case RX_WAKE_UP:
		if (access("/tmp/standby_mode", F_OK) == 0) {
			char command[40];
			snprintf(command, sizeof(command), "udpwol br-lan %s &", uci_safe_get("cameo.system.media_mac"));
			system(command);
			uci_free();
		}
		break;
	case UPDATE_WAN_STATUS:
		if (strncmp(ev_req->payload, "0", 1) == 0) {
			system("echo 0 > /sys/class/leds/wan/brightness");
		} else if (strncmp(ev_req->payload, "1", 1) == 0) {
			system("echo 1 > /sys/class/leds/wan/brightness");

			/*Hush....*/
			if (access("/etc/inittab.login", F_OK) == 0) {
				FILE *fp = NULL;
				int val;
				fp = fopen("/sys/class/gpio/gpio7/value", "r");
				if (!fp)
					break;
				val = fgetc(fp);
				fclose(fp);
				if (val == 48) {
					cprintf("Hush...\n", val);
					rename("/etc/inittab.login", "/etc/inittab");
				}
			}
		}
		break;

/*
	XXX Joe H. : This is a example for reponse date to sender.
		     Remove this example when first case is ready.
*/
	case 9999:
		ev_reply.id = 9999;
		ev_reply.length= 1;
		memset(ev_reply.payload, 0, MAX_PAYLOAD_LEN);
		ev_reply.payload[0] = 'x';
		send_event(destPID, &ev_reply);
		break;

	default:
		cprintf("unknow event id : %d\n", ev_req->id);
	}
}
