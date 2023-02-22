from typing import Optional


class PRG:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int):
        """
        Initialize values here
        :param security_parameter: n (from 1ⁿ)
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        """
        pass

    def generate(self, seed: int) -> str:
        """
        Generate the pseudo-random bit-string from `seed`
        :param seed: uniformly sampled seed
        :type seed: int
        """
        pass


class PRF:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, key: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param key: k, uniformly sampled key
        :type key: int
        """
        pass

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        pass


class Eavesdrop:
    def __init__(self, security_parameter: int, key: int, expansion_factor: int,
                 generator: int, prime_field: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param key: k, uniformly sampled key
        :type key: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        """
        pass

    def enc(self, message: str) -> str:
        """
        Encrypt Message against Eavesdropper Adversary
        :param message: message encoded as bit-string
        :type message: str
        """
        pass

    def dec(self, cipher: str) -> str:
        """
        Decipher ciphertext
        :param cipher: ciphertext encoded as bit-string
        :type cipher: str
        """
        pass


class CPA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key: int):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key: k
        :type key: int
        """
        pass

    def enc(self, message: int, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack
        :param message: m
        :type message: int
        :param random_seed: r
        :type random_seed: int
        """
        pass

    def dec(self, cipher: str) -> int:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        pass


class MAC:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int,
                 seed: int):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param seed: k
        :type seed: int
        """
        pass

    def mac(self, message: str, random_identifier: int) -> int:
        """
        Generate tag t
        :param random_identifier: r
        :type random_identifier: int
        :param message: message encoded as bit-string
        :type message: str
        """
        pass

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify whether the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        pass


class CBC_MAC:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int, keys: list[int]):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: q
        :type prime_field: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        :param keys: k₁, k₂
        :type keys: list[int]
        """
        pass

    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: m (with length l(n).n)
        :type message: str
        """
        pass

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        pass


class CCA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key_cpa: int, key_mac: int):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key_cpa: k1
        :type key_cpa: int
        :param key_mac: k2
        :type key_mac: int
        """
        pass

    def enc(self, message: str) -> str:
        """
        Encrypt message against Chosen Ciphertext Attack
        :param message: m
        :type message: str
        """
        pass

    def dec(self, cipher: str) -> Optional[str]:
        """
        Decrypt ciphertext to obtain message
        :param cipher: <c, t>
        :type cipher: str 
        """
        pass
        :type cipher: str
        """
        pass
