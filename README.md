# CoinonatX

![CoinonatX](logo.png)

CoinonatX is a PoS-based cryptocurrency.

CoinonatX uses
- libsecp256k1,
- libgmp,
- Boost1.55 OR Boost1.57,
- Openssl1.01m,
- Berkeley DB 4.8,
- QT5


Block Spacing: `90 Seconds`

Stake Minimum Age: `6 Hours`

Port: `44678`

RPC Port: `44578`


Linux build (see the [Wiki](coming soon) for dependencies)
-----------
- git clone https://github.com/xcxt-community/CoinonatX.git CoinonatX

- cd CoinonatX/src

- sudo make -f makefile.unix            # Headless CoinonatX

(optional)

- strip CoinonatXd

- sudo cp CoinonatXd /usr/local/bin




Windows build
-------------

- Download release from https://github.com/xcxt-community/CoinonatX/releases and unpack to C:/

- Download CoinonatX source from https://github.com/xcxt-community/CoinonatX/archive/master.zip

 - Unpack to C:/CoinonatX

- Install Perl for windows from the homepage http://www.activestate.com/activeperl/downloads

- Download Python 2.7 https://www.python.org/downloads/windows/

 - While installing python make sure to add python.exe to the path.

- Run msys.bat located in C:\MinGW49-32\msys\1.0

- cd /C/CoinonatX/src/leveldb

- Type "TARGET_OS=NATIVE_WINDOWS make libleveldb.a libmemenv.a" and hit enter to build leveldb

- Exit msys shell

- Open windows command prompt

- cd C:/dev

- Type "49-32-qt5.bat" and hit enter to run

- cd ../CoinonatX

- Type "qmake USE_UPNP=0" and hit enter to run

- Type "mingw32-make" and hit enter to start building. When it's finished you can find your .exe in the release folder.
