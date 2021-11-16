#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <ev.h>
#include <sutil.h>
#include <clink_ev.h>

#ifndef cprintf
#define cprintf(fmt, args...) do { \
        FILE *cfp = fopen("/dev/console", "w"); \
        if (cfp) { \
                fprintf(cfp, fmt, ## args); \
                fclose(cfp); \
        } \
} while (0)
#endif

void exec_event(int destPID, Event_ptr_t ev_req);

static int daemonize(int nochdir, int noclose, int fd0, int fd1, int fd2)
{
	int ret = 0;
	int err = 0;
	pid_t pid;
	int tmpfd = -1;
	int nullfd = -1;
	int i;

	/* Call fork() the first time. */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		ret = -1;
		goto OUT;
	}
	/* Terminate the parent process. */
	if (pid > 0)
		_exit(EXIT_SUCCESS);

	/* Create a new session. */
	pid = setsid();
	if (pid < 0) {
		perror("setsid");
		ret = -1;
		goto OUT;
	}

	/* Call fork() the second time. */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		ret = -1;
		goto OUT;
	}

	/* Terminate the parent process. */
	if (pid > 0)
		_exit(EXIT_SUCCESS);

	/* Change current working directory is nochdir is zero. */
	if (nochdir == 0) {
		if (chdir("/") < 0) {
			perror("chdir");
			ret = -1;
			goto OUT;
		}
	}

	/* Reset umask. */
	umask(0);

	/* Redirect stdin, stdout, and stderr if noclose is zero. */
	if (noclose == 0) {
		/* Close file descriptors 0, 1, and 2 first. */
		for (tmpfd = 0; tmpfd <= 2; tmpfd++) {
			if (close(tmpfd) < 0) {
				perror("close");
				ret = -1;
				goto OUT;
			}
		}

		/*
		 * Open /dev/null if any one of fd0, fd1, and fd2 is
		 * less than 0.
		 */
		if (fd0 < 0 || fd1 < 0 || fd2 < 0) {
			nullfd = open("/dev/null", O_RDWR);
			if (nullfd == -1) {
				/* open() had set errno. */
				perror("open");
				ret = -1;
				goto OUT;
			}
		} else {
			nullfd = -1;
		}

		/* Redirect stdin, stdout, and stderr. */
		for (i = 0; i <= 2; i++) {
			switch (i) {
			case 0: /* stdin */
				tmpfd = fd0;
				break;
			case 1: /* stdout */
				tmpfd = fd1;
				break;
			case 2: /* stderr */
				tmpfd = fd2;
				break;
			}

			/* Redirect to /dev/null if tmpfd < 0 */
			if (tmpfd < 0)
				ret = dup2(nullfd, i);
			else
				ret = dup2(tmpfd, i);

			if (ret < 0) {
				perror("dup2");
				ret = -1;
				goto OUT_CLOSE_NULL;
			}
		}
	}

OUT:
	return ret;

OUT_CLOSE_NULL:
	if (nullfd >= 0)
		close(nullfd);

	return ret;
}

static void task_loop(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct iovec iov;
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct nlmsghdr *nh;
	char *buf;
	int buf_len = NLMSG_SPACE(MAX_EVENT_LEN);
	int len;
	Event_ptr_t event;

	buf_len *= 2;
	buf = malloc(buf_len);
	if (buf == NULL)
		return;

	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base = buf;
	iov.iov_len = buf_len;

	memset(&msg, 0, sizeof(struct msghdr));
	memset(&sa, 0, sizeof(struct sockaddr_nl));
	msg.msg_name = (void *)&(sa);
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = recvmsg(watcher->fd, &msg, 0);

	if (len < 0)
		goto exit;

	nh = (struct nlmsghdr *)buf;
	event = (Event_ptr_t)NLMSG_DATA(nh);
	exec_event(nh->nlmsg_pid, event);

exit:
	free(buf);
	return;
}

static int init_netlink(void)
{
	struct ev_loop *loop = ev_default_loop(0);
	struct ev_io w_accept;
	struct sockaddr_nl addr;
	int sd;

	sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
	if (sd  < 0)
		return -1 ;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid(); /* self pid */

	// Bind socket to address
	if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		return -1;

	// Initialize and start a watcher to listen client requests
	ev_io_init(&w_accept, task_loop, sd, EV_READ);
	ev_io_start(loop, &w_accept);

	ev_loop(loop, 0);
	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fp = NULL;
	int ret = EXIT_FAILURE;

	if (daemonize(0, 0, -1, -1, -1) < 0)
		goto exit;

        fp = fopen("/proc/clink", "w");
        if (!fp) {
                perror("fopen");
                goto exit;
        }

        fprintf(fp, "%d\n", getpid());
        fclose(fp);

	init_netlink();

	ret = EXIT_SUCCESS;
exit:
	exit(ret);
}
