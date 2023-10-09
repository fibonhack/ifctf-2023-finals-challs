FROM python:3.8-slim as app

FROM pwn.red/jail
COPY --from=app / /srv

ARG FLAG=ifctf{placeholder}
COPY --chmod=775 ./src/prison.py /srv/app/run
RUN echo ${FLAG} > /srv/app/flag.txt

EXPOSE 5000

ENV JAIL_MEM=20M JAIL_TMP_SIZE=1M JAIL_PIDS=100 JAIL_CPU=0 JAIL_TIME=300
ENV JAIL_ENV_PYTHONUNBUFFERED=1 JAIL_ENV_PATH=/usr/local/bin:/usr/bin:/bin

# note: pwn.red/jail requires --privileged