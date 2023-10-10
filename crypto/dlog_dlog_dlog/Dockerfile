FROM python:slim AS python-crypto
RUN apt update
RUN apt install -y build-essential libgmp-dev
RUN pip install --no-cache-dir pycryptodome fastecdsa

FROM pwn.red/jail
COPY --from=python-crypto / /srv
COPY ./src/server.py /srv/app/
COPY ./src/secret.py /srv/app/
RUN mv /srv/app/server.py /srv/app/run
RUN chmod +x /srv/app/run

ENV JAIL_ENV_PYTHONUNBUFFERED=1 JAIL_TIME=120 JAIL_MEM=100M JAIL_CPU=100