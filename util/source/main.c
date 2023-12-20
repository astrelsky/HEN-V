#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SF_NOCACHE
#define	SF_NOCACHE	0x00000010
#endif

#ifndef SOCK_NONBLOCK
#define	SOCK_NONBLOCK	0x20000000
#endif

#define KLOG_PORT 9081

typedef struct tcp_socket {
	int fd;
	int server;
} tcp_socket_t;

static int klog = -1;

/*
static bool tcp_read(tcp_socket_t *restrict self, void *buf, size_t buflen) {
	size_t nread = 0;
	while (self->fd != -1 && nread < buflen) {
		struct pollfd pfd[] = {
			{.fd = self->fd, .events = POLLHUP | POLLRDNORM, .revents = 0},
			{.fd = self->server, .events = POLLHUP, .revents = 0}
		};
		int res = poll(pfd, sizeof(pfd) / sizeof(struct pollfd), INFTIM);
		if (res == -1 || res == 0) {
			// error occured
			return false;
		}

		if ((pfd[0].revents | pfd[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) {
			// connection closed
			close(self->fd);
			self->fd = -1;
			return false;
		}

		// we are ready to read
		ssize_t result = read(self->fd, (uint8_t *)(buf) + nread, buflen - nread);
		if (result == -1) {
			perror("read failed");
			return false;
		}
		nread += result;
	}
	return self->fd != -1;
}
*/

static bool tcp_write(tcp_socket_t *restrict self, const void *buf, size_t buflen) {
	size_t wrote = 0;
	while (self->fd != -1 && wrote < buflen) {
		struct pollfd pfd[] = {
			{.fd = self->fd, .events = POLLHUP | POLLWRNORM, .revents = 0},
			{.fd = self->server, .events = POLLHUP, .revents = 0}
		};
		int res = poll(pfd, sizeof(pfd) / sizeof(struct pollfd), INFTIM);
		if (res == -1 || res == 0) {
			// error occured
			return false;
		}

		if ((pfd[0].revents | pfd[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) {
			// connection closed
			close(self->fd);
			self->fd = -1;
			return false;
		}

		// we are ready to write
		const ssize_t result = write(self->fd, (uint8_t *)buf + wrote, buflen - wrote);
		if (result == -1) {
			perror("write failed");
			return false;
		}
		wrote += result;
	}
	return self->fd != -1;
}

static int klog_get_available_size(int fd) {
	int res = 0;
	const int err = ioctl(fd, FIONREAD, &res);
	if (err == -1) {
		perror("klog ioctl FIONREAD failed");
		return 0;
	}
	return res;
}

/*
static void klog_send_data(int s, int klog) {
	const int n = klog_get_available_size(klog);
	if (n == -1) {
		return;
	}
	off_t sent = 0;
	if (sendfile(klog, s, 0, 0, NULL, &sent, SF_NOCACHE | SF_SYNC) == -1) {
		perror("sendfile failed");
	} else {
		printf("sent %lld bytes from klog\n", sent);
	}
}
*/

static void send_klog(tcp_socket_t *restrict sock) {
	#define KLOG_BUF_SIZE 256
	static char klogbuf[KLOG_BUF_SIZE];
	int fd = open("/dev/klog", O_NONBLOCK, 0);
	if (fd == -1) {
		perror("open /dev/klog failed");
		exit(0); // NOLINT
		kill(getpid(), SIGKILL);
	}
	klog = fd;
	while (true) {
		struct pollfd readfds[] = {
			{.fd = fd, .events = POLLRDNORM, .revents = 0},
			{.fd = sock->fd, .events = POLLHUP, .revents = 0}
		};
		int res = poll(readfds, sizeof(readfds) / sizeof(struct pollfd), INFTIM);
		if (res == -1 || res == 0) {
			// error occured
			close(fd);
			klog = -1;
			return;
		}

		if (readfds[1].revents & POLLHUP) {
			// connection was closed
			close(fd);
			klog = -1;
			return;
		}

		//klog_send_data(sock->fd, fd);


		size_t n = klog_get_available_size(fd);
		ssize_t nread = read(fd, klogbuf, (n >= sizeof(klogbuf)) ? sizeof(klogbuf) : n);
		if (nread == -1) {
			// error occured
			perror("read failed");
			close(fd);
			klog = -1;
			return;
		}
		tcp_write(sock, klogbuf, nread);
	}
}

int main(void) {
	int server = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (server == -1) {
		perror("socket failed");
		return 0;
	}

	int value = 1;
	if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int)) == -1) {
		perror("setsockopt failed");
		close(server);
		return 0;
	}

	struct sockaddr_in server_addr = {
		.sin_len = 0,
		.sin_family = AF_INET,
		.sin_port = htons(KLOG_PORT),
		.sin_addr = {.s_addr = 0},
		.sin_zero = {0, 0, 0, 0, 0, 0, 0, 0}
	};

	if (bind(server, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("bind failed");
		close(server);
		return 0;
	}

	if (listen(server, 1) == -1) {
		perror("listen failed");
		close(server);
		return 0;
	}

	while (true) {
		struct pollfd pfd = {.fd = server, .events = POLLHUP | POLLRDNORM, .revents = 0};
		int res = poll(&pfd, 1, INFTIM);
		if (res == -1) {
			perror("poll failed");
			close(server);
			return 0;
		}
		if (res == 0 || pfd.revents & POLLHUP) {
			close(server);
			return 0;
		}
		tcp_socket_t sock = {
			.fd = accept(server, NULL, NULL),
			.server = server
		};
		if (sock.fd == -1) {
			if (errno != EBADF) {
				perror("accept failed");
				close(server);
				return 0;
			}
			continue;
		}
		send_klog(&sock);
		close(sock.fd);
	}
}

void _start(void) { // NOLINT
	int fd = open("/dev/console", O_WRONLY);
	if (fd == -1) {
		exit(0); // NOLINT
		kill(getpid(), SIGKILL);
	}
	dup2(fd, STDOUT_FILENO);
	dup2(STDOUT_FILENO, STDERR_FILENO);

	int err = main();

	if (klog != -1) {
		close(klog);
		klog = -1;
	}

	// sleep a bit to let the log flush
	usleep(1000000); // NOLINT

	exit(err); // NOLINT
	kill(getpid(), SIGKILL);
}
