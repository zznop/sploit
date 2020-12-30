FROM debian:10

RUN apt-get update && apt-get install -y \
    git                                  \
    make                                 \
    gcc                                  \
    gcc-arm-linux-gnueabi                \
    gcc-aarch64-linux-gnu                \
    gcc-mips-linux-gnu                   \
    gcc-mipsel-linux-gnu                 \
    gcc-powerpc-linux-gnu                \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp &&                                                                         \
    git clone https://github.com/aquynh/capstone.git --branch 4.0.2 --single-branch && \
    cd capstone &&                                                                     \
    make &&                                                                            \
    make install &&                                                                    \
    rm -rf /tmp/capstone
