FROM ubuntu:18.04
MAINTAINER Humphrey

RUN apt-get update
RUN apt-get install -y git build-essential wget
RUN apt-get install -y libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev
RUN apt-get install -y autoconf libtool pkg-config libboost-all-dev libssl-dev libprotobuf-dev protobuf-compiler libevent-dev libqt4-dev libcanberra-gtk-module software-properties-common
RUN apt-get install -y libminiupnpc-dev libzmq3-dev libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools
RUN cd ~ && git clone https://github.com/kebohan1/ourchain-dmplus.git
RUN wget http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz && tar -xvf db-4.8.30.NC.tar.gz && cd db-4.8.30.NC/build_unix/ && mkdir -p build && BDB_PREFIX=$(pwd)/build
RUN cd db-4.8.30.NC/build_unix/ && ../dist/configure --disable-shared --enable-cxx --with-pic --prefix=$BDB_PREFIX && make install
RUN cd ../..
RUN add-apt-repository ppa:bitcoin/bitcoin
RUN apt-get update
RUN apt-get install -y libdb4.8-dev libdb4.8++-dev libcpprest-dev
RUN cd ~/ourchain-dmplus && ./autogen.sh
RUN ./configure CPPFLAGS="-I${BDB_PREFIX}/include/ -O2" LDFLAGS="-L${BDB_PREFIX}/lib/" CRYPTO_LIBS="-lboost_system -lcrypto -lssl -lcpprest" --without-gui
RUN make -j 2 && make install && ldconfig
RUN cd ~ && wget https://golang.org/dl/go1.15.13.linux-amd64.tar.gz && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.5.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
RUN go version
RUN echo "export GOPATH=$HOME/go" >> ~/.profile
RUN echo "export PATH=$HOME/go/bin:$PATH" >> ~/.profile
RUN echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.profile
RUN echo "export PATH=$PATH:/usr/local/go/bin" >> /etc/profile
RUN go get github.com/ipfs/go-ipfs && cd ~/go/src/github.com/ipfs/go-ipfs && make install

