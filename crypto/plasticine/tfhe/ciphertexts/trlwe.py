import numpy as np
from tfhe.torus_polynomial import TorusPolynomial
from tfhe.poly import polymul


class RLWESecretKey:
    """
    Ring learning with error secret key. It's `k` polynomials of degree < `N` with binary coefficients. This same key will be used
    for encryption and decryption.
    """

    def __init__(self, big_n, k=1):
        assert k > 0, "k must be positive"
        self.big_n = big_n
        self.k = k
        self.data = [
            np.random.randint(0, 2, size=big_n, dtype=np.uint64) for _ in range(k)
        ]

    def bits_at(self, k):
        if not 0 <= k < self.k:
            raise ValueError(f"k must be between 0 and {self.k}")
        return self.data[k]


class TRLWE:
    def __init__(self, big_n, sigma, p, k=1):
        # we always use float64
        self.q = 2 ** 64
        self.big_n = big_n
        self.sigma = sigma
        self.p = p
        self.k = k
        self.mask = None
        self.b = None

    def serialize(self):
        return {
            "big_n": self.big_n,
            "sigma": self.sigma,
            "p": self.p,
            "k": self.k,
            "mask": [m.serialize() for m in self.mask],
            "b": self.b.serialize(),
        }

    @staticmethod
    def from_dict(data):
        trlwe = TRLWE(data.big_n, data.sigma, data.p, data.k)
        trlwe.mask = [TorusPolynomial.from_dict(m) for m in data.mask]
        trlwe.b = TorusPolynomial.from_dict(data.b)
        return trlwe

    @staticmethod
    def randn(big_n, sigma):
        """
        Generate a random torus polynomial element based on a normal distribution N(0, sigma ^ 2).
        """
        return TorusPolynomial.from_real(
            [np.random.randn() * sigma for _ in range(big_n)], big_n=big_n
        )

    def copy(self):
        new = TRLWE(self.big_n, self.sigma, self.p, self.k)
        new.mask = self.mask.copy()
        new.b = self.b.copy()
        return new

    def random_mask(self):
        """
        Random mask used to encrypt a torus element. It's a vector of size `k` of random torus polynomial
        elements (uniform distribution).
        """
        return [
            TorusPolynomial(
                np.random.randint(0, self.q, size=self.big_n, dtype=np.uint64),
                big_n=self.big_n,
            )
            for _ in range(self.k)
        ]

    def encrypt(self, sk, u):
        """
        Encrypt a torus polynomial message `u` with a secret key `sk`
        """
        self.mask = self.random_mask()
        encrypted_mask = TorusPolynomial([0], big_n=self.big_n)
        for i in range(self.k):
            sk_bits = sk.bits_at(i)
            ak = self.mask[i].data
            coeffs = polymul(sk_bits, ak)
            encrypted_mask += TorusPolynomial(coeffs, big_n=self.big_n)

        e = self.randn(self.big_n, self.sigma)
        self.b = encrypted_mask + u + e

    def decrypt(self, sk):
        """
        Decrypt a TLWE ciphertext into a torus element
        """
        if self.mask is None:
            raise RuntimeError("nothing is encrypted")

        encrypted_mask = TorusPolynomial([0], big_n=self.big_n)
        for i in range(self.k):
            sk_bits = sk.bits_at(i)
            ak = self.mask[i].data
            coeffs = polymul(sk_bits, ak)
            encrypted_mask += TorusPolynomial(coeffs, big_n=self.big_n)

        u_noisy = self.b - encrypted_mask
        # unwrapping/wrapping in Torus will just remove noise
        return TorusPolynomial.from_real(u_noisy.to_real(self.p), big_n=self.big_n)

    def have_same_param(self, other):
        """
        Check if `self` and `other` TELWE ciphertexts have the same parameters
        """
        if not isinstance(other, TRLWE):
            raise TypeError(f"can't check parameters with object of type {type(other)}")
        if self.q != other.q:
            return False
        if self.p != other.p:
            return False
        if self.k != other.k:
            return False
        if self.big_n != other.big_n:
            return False
        return True

    def __add__(self, other):
        if isinstance(other, TRLWE):
            if not self.have_same_param(other):
                raise ValueError("addition need to be done on TRLWE of same parameters")
            res = self.copy()
            for i in range(self.k):
                res.mask[i] = self.mask[i] + other.mask[i]
            res.b = self.b + other.b
            return res
        elif isinstance(other, TorusPolynomial):
            res = self.copy()
            res.b += other
            return res
        else:
            raise TypeError(f"don't support addition of TRLWE with {type(other)}")

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if isinstance(other, TRLWE):
            if not self.have_same_param(other):
                raise ValueError(
                    "subtraction need to be done on TRLWE of same parameters"
                )
            res = self.copy()
            for i in range(self.k):
                res.mask[i] -= other.mask[i]
            res.b -= other.b
            return res
        elif isinstance(other, TorusPolynomial):
            res = self.copy()
            res.b -= other
            return res
        else:
            raise TypeError(f"don't support addition of TRLWE with {type(other)}")

    def __rsub__(self, other):
        # TODO: negate first maybe?
        pass

    def __mul__(self, other):
        if isinstance(other, int):
            res = self.copy()
            res.b = self.b * other
            for i in range(len(res.mask)):
                res.mask[i] *= other
            return res
        else:
            raise TypeError(f"don't support multiplication of TRLWE with {type(other)}")

    def __rmul__(self, other):
        return self.__mul__(other)
