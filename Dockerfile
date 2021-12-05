FROM debian:latest

RUN apt update && \
    apt install -y wget gcc-mingw-w64-x86-64 autoconf make automake libtool patch

COPY build-tor-windows /
RUN chmod 755 /build-tor-windows

CMD [ "/build-tor-windows" ]