FROM python:slim AS python-crypto
RUN pip install --no-cache-dir pycryptodome

FROM pwn.red/jail
COPY --from=python-crypto / /srv
COPY ./src/* /srv/app/
COPY ./src/secret/* /srv/app/secret/
RUN mv /srv/app/server.py /srv/app/run
RUN chmod +x /srv/app/run

ENV JAIL_ENV_PYTHONUNBUFFERED=1 JAIL_TIME=120 JAIL_MEM=300M JAIL_CPU=500