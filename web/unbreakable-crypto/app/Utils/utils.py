from Crypto.Cipher import AES
from binascii import hexlify
from base64 import b64encode as b64enc, b64decode as b64dec
from Cryptodome.Util.Padding import pad, unpad
from PIL import Image, ImageFont, ImageDraw
import random, os


class Ticket:
    def __init__(self, data) -> None:
        self.data = self.parse(data)
        self.type = self.data["type"]
        self.name = self.data["name"]
        self.generateTicket()

    def parse(self, data):

        data = data[:-2].split(b'{"type": "')[1].split(b'", "name": "')
        # parsing it manually, due to the weird characters that might show in the solution.
        # filtering the quotes in order to optimize the taken time to forge the solution payload.
        # That might be a hint :D
        d = {}
        d["type"] = str(
            data[0].replace(b"\n", b"").replace(b'"', b"").replace(b"'", b"")
        )[2:-1]
        d["name"] = str(
            data[1].replace(b"\n", b"").replace(b"'", b"").replace(b'"', b"")
        )[2:-1]
        # print(d['type'])
        return d

    def generateTicket(self):
        ticket_template = "Utils/ticket.jpg"
        ticket = Image.open(ticket_template)

        font = ImageFont.truetype("Utils/Montserrat-Medium.ttf", 30)

        d = ImageDraw.Draw(ticket)
        rand_numb = str(random.randint(1, 10 ** 15))
        text = f"Name: {self.name}\n\nTicket Number: {rand_numb}"

        d.text((275, 200), text, (0, 0, 0), font=font)
        output = "./static/images/" + hex(int(rand_numb))[2:] + ".jpg"
        ticket.save(output)
        self.url = output[1:]


def encrypt(pt, key, iv):
    cryptor = AES.new(key, AES.MODE_CBC, iv)
    ct = cryptor.encrypt(pad(pt, 16))

    return b64enc(hexlify(iv + ct)).decode()


def decrypt(token, key):
    ct = b64dec(token).decode()

    iv = bytes.fromhex(ct[:32])
    ct = bytes.fromhex(ct[32:])

    cryptor = AES.new(key, AES.MODE_CBC, iv)
    pt = cryptor.decrypt(ct)

    return unpad(pt, 16)


def remove_tickets():
    for f in os.listdir("static/images"):
        os.remove(os.path.join("static/images", f))
