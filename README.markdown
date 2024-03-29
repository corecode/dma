dma -- DragonFly Mail Agent
===========================

dma is a small Mail Transport Agent (MTA), designed for home and
office use.  It accepts mails from locally installed Mail User Agents (MUA)
and delivers the mails either locally or to a remote destination.
Remote delivery includes several features like TLS/SSL support and
SMTP authentication.

dma is not intended as a replacement for real, big MTAs like sendmail(8)
or postfix(1).  Consequently, dma does not listen on port 25 for
incoming connections.


Install by a package manager
----------------------------

* FreeBSD `pkg install dma`
* Ubuntu `sudo apt install dma`
* Arch `yaourt -S dma`

Building
--------

In Linux:

	make

In BSD:

	cd bsd && make

Installation
------------

	make install sendmail-link mailq-link install-spool-dirs install-etc

See INSTALL for requirements and configuration options.


Contact
-------

Simon Schubert <2@0x2c.org>

See Also
--------

* [man dma](https://man.freebsd.org/cgi/man.cgi?query=dma)
* [dma on Arch Wiki](https://wiki.archlinux.org/title/Dma)
* [Awesome Selfhosted: MTAs](https://github.com/awesome-selfhosted/awesome-selfhosted#communication---email---mail-transfer-agents) - Other open source MTAs
