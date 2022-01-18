FROM python:3.6

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install nginx

RUN useradd ctf && \
    mkdir -p /ctf/TgbTlMvxWZW

COPY nginx.conf entrypoint.sh /ctf/TgbTlMvxWZW/

COPY app /ctf/TgbTlMvxWZW/app/

WORKDIR /ctf/TgbTlMvxWZW

RUN python -m pip install -r app/requirements.txt

RUN chmod +x entrypoint.sh

RUN /bin/echo -e "\n\n# You're going the right way, but you need to find a way to access the app files without knowing their path :)" >>/etc/passwd

USER ctf

ENTRYPOINT ["./entrypoint.sh"]
