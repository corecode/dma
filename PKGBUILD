# Contributor: Michael Krauss <hippodriver@gmx.net>
# $Id: PKGBUILD,v 1.2 2010/12/25 18:46:11 andres Exp $

pkgname="dma"
pkgver=0.8
pkgrel=2
pkgdesc="DragonFly BSD mail transport agent"
url="https://github.com/corecode/dma"
license=('BSD')
makedepends=('ed')
depends=('openssl')
backup=('etc/dma/auth.conf' 'etc/dma/dma.conf')
arch=('i686' 'x86_64')
source=("https://github.com/corecode/dma/archive/v$pkgver.tar.gz")
sha256sums=('dbebb3b74f4a0e3bf951470da5f2f065ef1302d633bee8e75e04a99e62c9558b')

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
