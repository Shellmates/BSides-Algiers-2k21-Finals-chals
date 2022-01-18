import os

from tfhe.ciphertexts.trlwe import *
from tfhe.torus_polynomial import TorusPolynomial

from typing import List
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi_utils.tasks import repeat_every


TOY_FLAG = "shellmates{post_quantum_security_da_best}"
FLAG = os.environ.get("FLAG", TOY_FLAG)

SIGMA = 2 ** -16
P = 2 ** 10
N = 2 ** 10
K = 2
Q = 2 ** 64
SK = RLWESecretKey(N, K)


def str_to_coeffs(flag: str) -> List[int]:
    return [ord(c) for c in flag]


def coeffs_to_str(coeffs: List[int]) -> str:
    return "".join([chr(c) for c in coeffs])


class TorusPolynomialModel(BaseModel):
    big_n: int
    coefficients: List[int]


class TRLWEModel(BaseModel):
    p: int
    big_n: int
    k: int
    sigma: float
    mask: List[TorusPolynomialModel]
    b: TorusPolynomialModel


app = FastAPI()


@app.on_event("startup")
@repeat_every(seconds=15)
def rotate_secret_key():
    global SK
    SK = RLWESecretKey(N, K)


@app.get("/encryptedFlag")
def encrypted_flag() -> TRLWEModel:
    u = TorusPolynomial.from_int(str_to_coeffs(FLAG), P, N)
    c = TRLWE(N, SIGMA, P, K)
    c.encrypt(SK, u)
    return c.serialize()


@app.post("/encrypt")
def encrypt(message: List[int]) -> TRLWEModel:
    u = TorusPolynomial.from_int(message, P * 16, N)
    c = TRLWE(N, SIGMA, P * 16, K)
    c.encrypt(SK, u)
    return c.serialize()


@app.post("/decrypt")
def decrypt(c: TRLWEModel):
    ct = TRLWE.from_dict(c)
    coeffs = ct.decrypt(SK).to_int(P)
    if coeffs_to_str(coeffs[: len(FLAG)]) == FLAG:
        return str_to_coeffs(TOY_FLAG)
    return coeffs
