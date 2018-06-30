[![Build Status](https://travis-ci.org/VirusTotal/c-vtapi.svg?branch=travis)](https://travis-ci.org/VirusTotal/c-vtapi)

VirusTotal C API library
This libary is designed to work with both the:	
  * The public API https://www.virustotal.com/en/documentation/public-api/
  * The private API https://www.virustotal.com/en/documentation/private-api/

Runtime Dependencies
  * curl or libcurl  (curl-devel package on some distributions)
  * janson version 2.2 (min) (2.5 or newer recommeded.  janson-devel on some distros)

Compiling Dependencies
  * automake, autoconf  (might be autotools package on your platform)
  * gcc
  * libtool

Debian or Ubuntu Dependencies:
```
sudo apt-get install automake autoconf libtool libjansson-dev libcurl4-openssl-dev
```

Redhat, Fedora, Centos or RPM based distros:
```
yum install libtool jansson-devel libcurl-devel
```

To compile on Linux, BSD, or Mac OS X:
```
autoreconf -fi
./configure
make
sudo make install
```

If you wish to build the examples in the 'examples' directory:
```
autoreconf -fi
./configure --enable-examples
make
sudo make install
```

If you have doxygen installed on your system you may optionally generate developer doxygen docs:
 ```
make doxygen-doc
```

Usage on MS Windows is partially functioal now, but requires more patches to be fully supported.

Windows compilation:
```
* Installl mingw
  *  mingw32 gcc-g++
  *  mingw32-autoconf
  *  mingw32-automake
* compile libcurl  (See their docs on windows compile)
```

Windows compilation (MS Visual Studio)
 * install MS Visual Studio 2013
 * install CMake
 * Compile jansson  (see janson docs)
 * Compile curl  (see janson docs)
	

See Examples in examples/
For some example test programs using API.
```
url --apikey=YOUR_KEY --scan http://youtube.com
url --apikey=YOUR_KEY --report http://youtube.com


scan --help
./scan --apikey YOUR_KEY --filescan /bin/ls
./scan --apikey YOUR_KEY --report HASH
```
