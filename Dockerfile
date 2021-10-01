FROM ubuntu:20.04

RUN apt update && apt install -y git vim build-essential doxygen
RUN apt install -y automake autoconf libtool libjansson-dev libcurl4-openssl-dev
WORKDIR /work/vtapi
RUN git clone https://github.com/CASL0/c-vtapi.git

ENTRYPOINT bash