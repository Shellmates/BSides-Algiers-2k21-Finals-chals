import numpy as np
from tfhe.poly import polymod


class TorusPolynomial:
    """
    Polynomial (mod X^n + 1) with Torus coefficients
    """

    q = 2 ** 64

    def __init__(self, coefficients=[], big_n=1024):
        """
        :param coefficients: polynomial coefficients in order of increasing degree
        :param big_n: polynomial modulus degree (X ^ big_n + 1)
        """
        self.data = np.array(coefficients, dtype=np.uint64)
        self.big_n = big_n
        self._apply_poly_mod()

    def serialize(self):
        return {
            "big_n": self.big_n,
            "coefficients": self.data.tolist(),
        }

    @staticmethod
    def from_dict(data):
        return TorusPolynomial(data.coefficients, data.big_n)


    def _apply_poly_mod(self):
        self.data = polymod(self.data, self.big_n, self.q)

    def copy(self):
        new = TorusPolynomial(self.data.copy(), big_n=self.big_n)
        new.q = self.q
        return new

    @classmethod
    def from_real(cls, values, big_n=None):
        """
        Takes a list of real numbers from [0, 1) and outputs a TorusPolynomial object representing it
        """
        if isinstance(values, float):
            values = [values]
        coeffs = []
        for value in values:
            # if value < 0 or value >= 1:
            #     print(
            #         f"Warning: value {value} is not in the range [0, 1), it will be converted into a real modulo 1 = {value % 1}"
            #     )
            value = value % 1
            coeffs.append((value * cls.q) % cls.q)
        if big_n is None:
            return TorusPolynomial(coeffs)
        else:
            return TorusPolynomial(coeffs, big_n=big_n)

    def to_real(self, p):
        """
        Takes a TorusPolynomial element and outputs its real representation in [0, 1) using
        log2(p) bits of precision
        """
        result = []
        for coeff in self.data:
            # this mask any bits not included in the left most log2(p) bits
            rounded = np.uint64(np.round(coeff / (self.q / p))) / p
            result.append(rounded)
        # fill zero coefficients
        result = result + [0] * (self.big_n - len(result))
        return result

    @classmethod
    def from_int(cls, values, p, big_n=None):
        """
        Takes a list of integer numbers in [0, p) and outputs a Torus object representing it
        using log2(p) bits of precision
        """
        if isinstance(values, (int, np.uint64, np.int64)):
            values = [values]
        coeffs = []
        for value in values:
            if value < 0 or value >= p:
                print(
                    f"Warning: value {value} is not in the range [0, p), it will be converted into an integer modulo p = {value % p}"
                )
            value = (int(value % p) * (cls.q / p)) % cls.q
            coeffs.append(value)

        if big_n is None:
            return TorusPolynomial(coeffs)
        else:
            return TorusPolynomial(coeffs, big_n=big_n)

    def to_int(self, p):
        """
        Takes a TorusPolynomial element and outputs its integer representation in [0, p) using
        log2(p) bits of precision
        """
        result = []
        for coeff in self.data:
            result.append(int(np.uint64(np.round(coeff / (self.q / p))) % np.uint64(p)))
        # fill zero coefficients
        result = result + [0] * (self.big_n - len(result))
        return result

    @classmethod
    def from_float(cls, values, p, data_range, big_n=None):
        """
        Takes a list of float numbers in [data_range[0], data_range[1]) and outputs a Torus object representing it
        using log2(p) bits of precision
        """
        if isinstance(values, float):
            values = [values]
        if not isinstance(data_range, (list, tuple)):
            raise TypeError("data_range must be a tuple or list")
        if len(data_range) != 2:
            raise ValueError("data_range must be a tuple or list of length 2")
        if data_range[0] >= data_range[1]:
            raise ValueError("data_range[0] must be lower than data_range[1]")
        low = data_range[0]
        high = data_range[1]
        delta = high - low
        offset = low

        coeffs = []
        for value in values:
            if value < low or value >= high:
                print(
                    f"Warning: value {value} is not in the range [{low}, {high}), it will be converted into a float in that range => {(value - offset) % delta + offset}"
                )
            # convert to int in [0, p)
            value = float((value - offset) % delta)
            step = delta / p
            coeffs.append(((round(value / step) % p) * (cls.q / p)) % cls.q)

        if big_n is None:
            return TorusPolynomial(coeffs)
        else:
            return TorusPolynomial(coeffs, big_n=big_n)

    def to_float(self, p, data_range):
        """
        Takes a Torus element and outputs its float representation in [data_range[0], data_range[1]) using
        log2(p) bits of precision
        """
        if not isinstance(data_range, (list, tuple)):
            raise TypeError("data_range must be a tuple or list")
        if len(data_range) != 2:
            raise ValueError("data_range must be a tuple or list of length 2")
        if data_range[0] >= data_range[1]:
            raise ValueError("data_range[0] must be lower than data_range[1]")
        low = data_range[0]
        high = data_range[1]
        delta = high - low
        offset = low
        step = delta / p
        result = []
        for coeff in self.data:
            int_value = np.uint64(np.round(coeff / (self.q / p))) % np.uint64(p)
            result.append(int_value * step + offset)
        # fill zero coefficients
        result = result + [0] * (self.big_n - len(result))
        return result

    def __add__(self, other):
        if isinstance(other, TorusPolynomial):
            if self.big_n != other.big_n:
                raise ValueError(
                    f"Polynomial modulus degree don't match {self.big_n} and {other.big_n}"
                )
            rs = self.data.tolist() + [0] * (self.big_n - len(self.data))
            ls = other.data.tolist() + [0] * (self.big_n - len(other.data))
            return TorusPolynomial(
                [(x + y) % self.q for x, y in zip(rs, ls)], big_n=self.big_n
            )
        else:
            raise TypeError(
                f"doesn't support addition of torus polynomial elements with {type(other)}"
            )

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if isinstance(other, TorusPolynomial):
            if self.big_n != other.big_n:
                raise ValueError(
                    f"Polynomial modulus degree don't match {self.big_n} and {other.big_n}"
                )
            rs = self.data.tolist() + [0] * (self.big_n - len(self.data))
            ls = other.data.tolist() + [0] * (self.big_n - len(other.data))
            return TorusPolynomial(
                [(x - y) % self.q for x, y in zip(rs, ls)], big_n=self.big_n
            )
        else:
            raise TypeError(
                f"doesn't support subtraction of torus polynomial elements with {type(other)}"
            )

    def __rsub__(self, other):
        if isinstance(other, TorusPolynomial):
            if self.big_n != other.big_n:
                raise ValueError(
                    f"Polynomial modulus degree don't match {self.big_n} and {other.big_n}"
                )
            rs = other.data.tolist() + [0] * (self.big_n - len(other.data))
            ls = self.data.tolist() + [0] * (self.big_n - len(self.data))
            return TorusPolynomial(
                [(x - y) % self.q for x, y in zip(rs, ls)], big_n=self.big_n
            )
        else:
            raise TypeError(
                f"doesn't support subtraction of torus polynomial elements with {type(other)}"
            )

    def __mul__(self, other):
        if isinstance(other, int):
            other = np.uint64(other)
        if isinstance(other, np.uint64):
            return TorusPolynomial(self.data * other, big_n=self.big_n)
        else:
            raise TypeError(
                f"doesn't support multiplication of torus elements with {type(other)}"
            )

    def __rmul__(self, other):
        return self.__mul__(other)
