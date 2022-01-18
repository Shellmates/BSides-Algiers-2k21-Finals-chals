FROM python:3-alpine

RUN adduser --disabled-password --no-create-home ctf

COPY challenge /challenge/

WORKDIR /challenge

RUN pip install -r requirements.txt

RUN chmod +x challenge.py

ENTRYPOINT ["python","./challenge.py"]
