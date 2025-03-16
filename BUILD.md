## Prerequsuites
You need to have cmake and meson installed. 
Scorpi depends on libwebsockets library  

## Building libwebsockets library
```
git clone https://github.com/warmcat/libwebsockets.git
cd libwebsockets
mkdir build; cd build
cmake -DLWS_WITH_SSL=0 ..
make
sudo make install
```

## Building Scorpi
Make sure to export CODESIGN_IDENTITY env variable. It should be in form 'Developer ID Application: [Your Team]'
```
CC=clang meson setup --buildtype=release builddir
meson compile -C builddir
```