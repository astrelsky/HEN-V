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
  the appropriate GPU_READ and GPU_WRITE mmap flags as necessary.


Payloads
--------

* The payload server will listen on port **9022**. This is to prevent conflicts
  with the elf loader used to start HEN-V.
* Payloads are run as an app local process (subprocess) by HEN-V.
* Up to 6 payloads may be running simultaneously.
  This may be extended to 15 in the future if editing the budget becomes possible.
* Payloads may communicate with HEN-V using the socket fd 3.
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
* Full details and examples are shown in `commands.md`.


KLOG and FTP
------------

* To make life easier, a klog and ftp server have been put into their own application.
  This prevents them from consuming payload slots and keeps them running if HEN-V is killed.


Credits
-------

* If you have a list, add it. Otherwise, you know who you are.
