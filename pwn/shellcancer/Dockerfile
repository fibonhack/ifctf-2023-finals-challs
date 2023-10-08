# DO NOT release this file. This is literally security by obscurity.
FROM ubuntu@sha256:b4b521bfcec90b11d2869e00fe1f2380c21cbfcd799ee35df8bd7ac09e6f63ea AS cusumano
RUN apt-get update && \
        apt-get install -y python3 && \
        apt-get clean autoclean && \
        apt-get autoremove --yes && \
        rm -rf /var/lib/{apt,dpkg,cache,log}/

RUN mkdir -p /app/src/
COPY attachments/server.py /app
COPY attachments/shellcancer /app


FROM pwn.red/jail
COPY --from=cusumano / /srv

RUN mkdir -p /srv/app/5ac38c9dbd2cff2892cb085953144cfbcf891c05
COPY flag.txt /srv/app/5ac38c9dbd2cff2892cb085953144cfbcf891c05/flag.txt
COPY run.sh /srv/app/run
RUN chmod +x /srv/app/run


ENV JAIL_TMP_SIZE=10M JAIL_TIME=60 JAIL_MEM=10M JAIL_POW=7500
