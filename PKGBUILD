# Contributor: Michael Krauss <hippodriver@gmx.net>
# $Id: PKGBUILD,v 1.2 2010/12/25 18:46:11 andres Exp $

pkgname="dma"
pkgver=0.12
pkgrel=1
pkgdesc="DragonFly BSD mail transport agent"
url="https://github.com/corecode/dma"
license=('BSD')
makedepends=('ed')
depends=('openssl')
provides=('smtp-forwarder')
conflicts=('smtp-forwarder')
backup=('etc/dma/auth.conf' 'etc/dma/dma.conf')
arch=('i686' 'x86_64')
source=("https://github.com/corecode/dma/archive/v$pkgver.tar.gz")
sha256sums=('054a40203d43bc1182dcadf2375ccf01944329dce472444acb42d56cf01de367')

buildargs="PREFIX=/usr LIBEXEC=/usr/lib/dma SBIN=/usr/bin"

build() {
	cd dma-$pkgver
	make $buildargs
}

package() {
	cd dma-$pkgver
	make install sendmail-link mailq-link install-etc DESTDIR=$pkgdir $buildargs

	install -d -o root -g mail -m 2775 $pkgdir/var/spool/dma

        install -d -m 755 $pkgdir/usr/share/licenses/$pkgname
	install LICENSE $pkgdir/usr/share/licenses/$pkgname
}
