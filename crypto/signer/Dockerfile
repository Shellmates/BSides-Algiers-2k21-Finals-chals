FROM python:3.9

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip pycryptodome

RUN useradd ctf && \
    mkdir /challenge

COPY challenge /challenge

WORKDIR /challenge

RUN chmod +x entrypoint.sh challenge.py && \
    chown -R root:root .

USER ctf

ENTRYPOINT ["./entrypoint.sh"]
