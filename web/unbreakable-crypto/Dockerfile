FROM python:3.9.5-alpine

RUN apk add --no-cache --virtual .build-deps gcc musl-dev  chromium udev linux-headers nginx python3-dev jpeg-dev zlib-dev g++ freetype-dev 
 
RUN mkdir  /ctf 

COPY nginx.conf entrypoint.sh /ctf/

COPY app /ctf/app/

WORKDIR /ctf

RUN pip install -r app/requirements.txt

RUN pip install uwsgi

RUN chmod 777 /ctf/app/static/

RUN chmod +x entrypoint.sh 

ENTRYPOINT ["/bin/sh","./entrypoint.sh"]
