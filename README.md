HEN-V
=====


Homebrew Apps
-------------

* Homebrew apps may have any `applicationCategoryType`.
  However, only PS5 game and daemon modes have been tested.
* The only requirements for a homebrew app are that it lives in `/system_ex/app`
  and that a loadable ELF file named `homebrew.elf` must exist in the app root directory `/app0`.
* Homebrew apps will remain in the sandbox when run. This is make accessing
  resources such as system fonts easier.
* To ensure the GPU can read/write data sections of an elf, all data sections are mapped with
  the appropriate `GPU_READ` and `GPU_WRITE` mmap flags as necessary.


Payloads
--------

* The payload server will listen on port **9022**. This is to prevent conflicts
  with the elf loader used to start HEN-V.
* Payloads are run as an app local process (subprocess) by HEN-V.
* Up to 6 payloads may be running simultaneously.
  This may be extended to 15 in the future if editing the budget becomes possible.
* All payloads have a default sighandler installed automatically for signals that will
  cause abnormal termination. If a payload crashes, even though they are separate
  processes, `SysCore` will terminate the entire application and all running local processes.
  The default sighandler is as follows; if you don't like it, install your own.

```c
static void default_handler(int sig) {
    (void) sig;
    kill(getpid(), SIGKILL);
}
```


Commands
--------

* Commands may be sent to HEN-V from a payload or application.
* Full details and examples are shown in [commands.md](commands.md).


KLOG and FTP
------------

* To make life easier, a klog and ftp server have been put into their own application.
  This prevents them from consuming payload slots and keeps them running if HEN-V is killed.
* The klog server listens on port `9081`.
* The FTP server listens on port `1337`.


Kernel Read/Write Server
------------------------

* For processes which may need kernel r/w that were started from an alternate
  userland entrypoing (bdj, webkit, masticore, etc) kernel r/w may be requested
  by sending the following to port `1338`.
```c
typedef struct kernelrw_request {
	int pid;
	int master;
	int victim;
} kernelrw_request_t;
```
* The master and victim sockets **must** be configured properly prior to making the request.
  An example of how to prepare the sockets is shown below.
```c
int configure_sockets(int *restrict master, int *restrict victim) {
	const size_t IN6_PKTINFO_SIZE = 20;
	*master = -1;
	*victim = -1;
	*master = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (*master == -1) {
		return -1;
	}
	*victim = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (*victim == -1) {
		close(*master);
		*master = -1;
		return -1;
	}
	uint32_t buf[] = {IN6_PKTINFO_SIZE, IPPROTO_IPV6, IPV6_TCLASS, 0, 0, 0};
	if (setsockopt(*master, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, sizeof(buf))) {
		close(*master);
		close(*victim);
		*master = -1;
		*victim = -1;
		return -1;
	}
	memset(buf, 0, sizeof(buf));
	if (setsockopt(*victim, IPPROTO_IPV6, IPV6_PKTINFO, NativeMemory.addressOf(buf), IN6_PKTINFO_SIZE)) {
		close(*master);
		close(*victim);
		*master = -1;
		*victim = -1;
		return -1;
	}
	return 0;
}
```
* The response from the server will be as follows:
```c
typedef struct kernelrw_response {
	uintptr_t kernel_base; // will be 0 if an error occured
	uint32_t error_length; // includes the NULL terminator
	char error[error_length];
} kernelrw_response_t;
```

Credits
-------

* If you have a list of people who helped with everything to get this far, add it. Otherwise, you know who you are.
