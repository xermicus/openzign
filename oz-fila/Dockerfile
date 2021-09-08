FROM rust:latest as builder
WORKDIR /usr/src/vxug
COPY . .
RUN cargo install --path .

FROM debian:buster-slim

RUN apt-get update
RUN apt-get install make gcc git yara --fix-missing -y
WORKDIR /opt
RUN git clone https://github.com/Yara-Rules/rules
COPY vxug.yar rules/
RUN git clone https://github.com/radareorg/radare2
RUN cd radare2 && sys/install.sh

COPY --from=builder /usr/local/cargo/bin/vxug /usr/local/bin/vxug
CMD ["vxug"]
