
FROM ubuntu:22.04 AS kernel
RUN apt-get update && \
        apt-get install -y qemu-system-x86 python3 unzip cpio
# && \
        # apt-get clean autoclean && \
        # apt-get autoremove --yes && \
        # rm -rf /var/lib/{apt,dpkg,cache,log}/

RUN mkdir -p /app/src/
COPY dist/rinux.zip /app/src/
RUN cd /app/src && unzip rinux.zip
RUN cd /app/src/src && unzip repo.zip
RUN cp /app/src/src/target/stage0/release/bootloader /app/bootloader
RUN cp /app/src/src/target/x86_64-unknown-none/release/kernel /app/kernel


FROM pwn.red/jail
COPY --from=kernel / /srv

COPY server.py /srv/app/server.py
COPY run.sh /srv/app/run
COPY flag.txt /srv/app/flag.txt
RUN chmod +x /srv/app/run
RUN chmod -R 777 /srv/app


ENV JAIL_TMP_SIZE=100M JAIL_TIME=15 JAIL_MEM=500M JAIL_POW=7500
