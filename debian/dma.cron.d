# Flush the dma mail transfer agent's queue every five minutes.
#
*/5 *	* * *	root	[ -x /usr/sbin/dma-migrate ] && /usr/sbin/dma-migrate; [ -x /usr/sbin/dma ] && /usr/sbin/dma -q1
