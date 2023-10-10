FROM python:slim AS python-crypto
# RUN pip install --no-cache-dir pycryptodome

FROM pwn.red/jail
COPY --from=python-crypto / /srv
COPY ./src/server.py /srv/app/run
RUN chmod +x /srv/app/run
COPY ./src/secret.py /srv/app/secret.py

ENV JAIL_TIME=120 JAIL_MEM=300M JAIL_CPU=500 JAIL_POW=45000