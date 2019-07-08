#!/bin/sh

mkdir -p root/usr/local/bin
mkdir -p root/etc/stoneflashtool
mkdir -p root/usr/share/stoneflashtool

cp ../flashtool.py root/usr/local/bin/stoneflashtool
cp ../config-example.ini root/etc/stoneflashtool/config.ini
cp ../requirements.txt root/usr/share/stoneflashtool/

chmod go-rwx root/etc/stoneflashtool/config.ini

sed -i s/##BUILDNR##/${BUILD_NUMBER}/ root/DEBIAN/control

mv root stoneflashtool_1.0-${BUILD_NUMBER}

fakeroot dpkg-deb --build stoneflashtool_1.0-${BUILD_NUMBER}
