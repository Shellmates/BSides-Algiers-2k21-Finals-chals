FROM python:3.6

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install nginx

RUN useradd ctf && \
    mkdir -p /ctf /tmp/slasher_app/uploads

COPY nginx.conf entrypoint.sh /ctf/

COPY app /ctf/app/

COPY flag.txt /

WORKDIR /ctf

RUN python -m pip install -r app/requirements.txt

RUN chmod +x entrypoint.sh && \
    chown -R ctf:ctf /tmp/slasher_app && \
    mv /flag.txt /flag

USER ctf

ENTRYPOINT ["./entrypoint.sh"]
