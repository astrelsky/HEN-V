#include "log.h"
#include "tcp.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <unistd.h>

static int tcp_bind(int server, short port) {
	struct sockaddr_in server_addr = {
		.sin_len = 0,
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr = {.s_addr = 0},
		.sin_zero = {0, 0, 0, 0, 0, 0, 0, 0}
	};
	if (bind(server, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		LOG_PERROR("bind failed");
		return -1;
	}
	return 0;
}

static int tcp_listen(int server, int backlog) {
	if (listen(server, backlog) == -1) {
		LOG_PERROR("listen failed");
		return -1;
	}
	return 0;
}

int tcp_init(tcp_socket_t *restrict self, int backlog, short port) {
	*self = (tcp_socket_t) {
		.fd = -1,
		.server = -1
	};
	const int server = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (server == -1) {
		LOG_PERROR("socket failed");
		return -1;
	}

	const int value = 1;
	if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int)) == -1) {
		LOG_PERROR("setsockopt failed");
		close(server);
		return -1;
	}

	if (tcp_bind(server, port)) {
		LOG_PRINTLN("tcp_bind failed");
		close(server);
		return -1;
	}
	if (tcp_listen(server, backlog)) {
		LOG_PRINTLN("tcp_listen failed");
		close(server);
		return -1;
	}
	self->server = server;
	return 0;
}

int tcp_read(const tcp_socket_t *restrict self, void *buf, size_t buflen) {
	if (self->fd == -1 || self->server == -1) {
		return -1;
	}
	size_t nread = 0;
	while (self->fd != -1 && nread < buflen) {
		struct pollfd pfd[] = {
			{.fd = self->fd, .events = POLLHUP | POLLRDNORM, .revents = 0},
			{.fd = self->server, .events = POLLHUP, .revents = 0}
		};
		const int res = poll(pfd, sizeof(pfd) / sizeof(struct pollfd), INFTIM);
		if (res == -1) {
			if (errno != REST_MODE_ERR) {
				LOG_PERROR("poll failed");
			}
			return -1;
		}
		if (res == 0) {
			// error occured
			return -1;
		}

		if ((pfd[0].revents | pfd[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) {
			// connection closed
			return -1;
		}

		// we are ready to read
		const ssize_t result = read(self->fd, (uint8_t *)(buf) + nread, buflen - nread);
		if (result == -1) {
			LOG_PERROR("read failed");
			return -1;
		}
		nread += result;
	}
	return self->fd == -1;
}

int tcp_write(const tcp_socket_t *restrict self, const void *buf, size_t buflen) {
	if (self->fd == -1 || self->server == -1) {
		return -1;
	}
	size_t wrote = 0;
	while (self->fd != -1 && wrote < buflen) {
		struct pollfd pfd[] = {
			{.fd = self->fd, .events = POLLHUP | POLLWRNORM, .revents = 0},
			{.fd = self->server, .events = POLLHUP, .revents = 0}
		};
		const int res = poll(pfd, sizeof(pfd) / sizeof(struct pollfd), INFTIM);
		if (res == -1) {
			if (errno != REST_MODE_ERR) {
				LOG_PERROR("poll failed");
			}
			return -1;
		}
		if (res == 0) {
			// error occured
			return -1;
		}

		if ((pfd[0].revents | pfd[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) {
			// connection closed
			return -1;
		}

		// we are ready to write
		const ssize_t result = send(self->fd, (uint8_t *)buf + wrote, buflen - wrote, MSG_NOSIGNAL);
		if (result == -1) {
			LOG_PERROR("tcp_write send failed");
			return -1;
		}
		wrote += result;
	}
	return self->fd == -1;
}

int tcp_accept(tcp_socket_t *restrict self) {
	if (self->server == -1) {
		return -1;
	}
	struct pollfd pfd = {.fd = self->server, .events = POLLHUP | POLLRDNORM, .revents = 0};
	const int res = poll(&pfd, 1, INFTIM);
	if (res == -1) {
		if (errno != REST_MODE_ERR) {
			LOG_PERROR("poll failed");
		}
		tcp_close(self);
		return -1;
	}
	if (res == 0 || pfd.revents & POLLHUP) {
		tcp_close(self);
		return -1;
	}
	self->fd = accept(self->server, NULL, NULL);
	if (self->fd == -1) {
		const int err = errno;
		tcp_close(self);
		if (err != EBADF) {
			LOG_PERROR("accept failed");
			return -1;
		}
		return REST_MODE_ERR;
	}
	return 0;
}

int tcp_close(tcp_socket_t *restrict self) {
	int res = 0;
	if (self->fd != -1) {
		res = close(self->fd);
		if (res) {
			LOG_PERROR("close failed");
		}
		self->fd = -1;
	}
	if (self->server != -1) {
		res |= close(self->server);
		self->server = -1;
	}
	return res;
}

int tcp_close_connection(tcp_socket_t *restrict self) {
	if (self->fd == -1) {
		return 0;
	}
	const int res = close(self->fd);
	if (res) {
		LOG_PERROR("close failed");
	}
	self->fd = -1;
	return res;
}
