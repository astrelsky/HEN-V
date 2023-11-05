HEN-V
=====


Homebrew Apps
-------------

* The only requirements for a homebrew app are that it lives in `/system_ex/app`
  and that a loadable ELF file named `homebrew.elf` must exist in the app root directory `/app0`.


Payloads
--------

* Payloads are run as a subprocess by HEN-V.
* Up to 15 payloads may be running simultaneously.
* Payloads may communicate with HEN-V using the socket fd 3.
  All communication must follow the same format used with app messaging.
