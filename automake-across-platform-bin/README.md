## vd_host 
### linux 
```
./confgure --prefix=/usr
make
ls ./src/vd_host

build rpm:
mkdir -p ~/rpmbuild/SPEC
mkdir -p ~/rpmbuild/SOURCES

cp -r vd_host-1.0.0  ~/rpmbuild/SOURCES
cp -r vd_host-1.0.0/vd_host.spec ~/rpmbuild/SPEC

cd ~/rpmbuild/SOURCES
tar czvf vd_host-1.0.0.tar.gz ./vd_host-1.0.0

cd ~/rpmbuild/SPEC
rpmbuild -ba ./

ls ~/rpmbuild/RPMS 

```
### windows
```
mingw64-configure
mingw64-make
ls ./src/vd_host.exe 

build package:
copy to windows platform  and make install package.
```