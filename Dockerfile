FROM rust as builder
WORKDIR /usr/src/oz-fila
COPY . .
RUN rustup default nightly
RUN cargo install --path oz-fila
RUN cargo install --path oz-indexer
RUN cargo install --path oz-api

FROM debian:buster-slim

RUN apt-get update
RUN apt-get install make gcc git yara --fix-missing -y
WORKDIR /opt
RUN git clone https://github.com/Yara-Rules/rules
COPY oz-fila/vxug.yar rules/
RUN git clone https://github.com/radareorg/radare2
RUN cd radare2 && sys/install.sh

COPY --from=builder /usr/local/cargo/bin/oz-fila /usr/local/bin
COPY --from=builder /usr/local/cargo/bin/oz-indexer /usr/local/bin
COPY --from=builder /usr/local/cargo/bin/oz-api /usr/local/bin
