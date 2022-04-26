FROM dmplus/ourchain-base
MAINTAINER Humphrey

RUN cd ~ && git clone https://github.com/kebohan1/ourchain-dmplus.git
RUN cd ~/ourchain-dmplus && git checkout contract_call_by_sys_test && ./autogen.sh && \
./configure CPPFLAGS="-I${BDB_PREFIX}/include/ -O2" LDFLAGS="-L${BDB_PREFIX}/lib/" CRYPTO_LIBS="-lboost_system -lcrypto -lssl -lcpprest" --without-gui && \
make -j 12 && make install && ldconfig
# RUN cd ~ && wget https://golang.org/dl/go1.18.1.linux-amd64.tar.gz && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.18.1.linux-amd64.tar.gz
# ENV PATH=$PATH:/usr/local/go/bin
# RUN go version
# RUN echo "export GOPATH=$HOME/go" >> ~/.profile
# RUN echo "export PATH=$HOME/go/bin:$PATH" >> ~/.profile
# RUN echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.profile
# RUN echo "export PATH=$PATH:/usr/local/go/bin" >> /etc/profile
# # RUN git clone https://github.com/ipfs/go-ipfs.git && cd go-ipfs && make install
# RUN cd ~ && wget https://dist.ipfs.io/go-ipfs/v0.12.0/go-ipfs_v0.12.0_linux-amd64.tar.gz && \
# tar -xvzf go-ipfs_v0.12.0_linux-amd64.tar.gz && cd go-ipfs && ./install.sh
# RUN ipfs --version
# CMD ["ipfs daemon"]

