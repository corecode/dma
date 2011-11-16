# Contributor: Michael Krauss <hippodriver@gmx.net>
# $Id: PKGBUILD,v 1.2 2010/12/25 18:46:11 andres Exp $

pkgname="dma"
pkgver=0.5
pkgrel=1
pkgdesc="DragonFly BSD mail transport agent"
url="https://gitorious.org/dma"
license=('BSD')
makedepends=('ed')
depends=('openssl')
backup=('etc/dma/auth.conf' 'etc/dma/dma.conf')
arch=('i686' 'x86_64')
source=("https://github.com/corecode/dma/tarball/v$pkgver")
sha256sums=('63b45c1b3fc3058f26aa59c5e29c8352ebe47a778fedbd2c33b52a3f3b2b55c6')

build() {
	cd corecode-dma-*
	make PREFIX=/usr LIBEXEC=/usr/lib/dma
}

package() {
	cd corecode-dma-*
	make install sendmail-link mailq-link install-etc DESTDIR=$pkgdir PREFIX=/usr LIBEXEC=/usr/lib/dma

	install -d -o root -g mail -m 2775 $pkgdir/var/spool/dma

        install -d -m 755 $pkgdir/usr/share/licenses/$pkgname
	install LICENSE $pkgdir/usr/share/licenses/$pkgname
}
