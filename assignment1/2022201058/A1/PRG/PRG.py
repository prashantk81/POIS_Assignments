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
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.expansion_factor = expansion_factor
        pass

    def generate(self, seed: int) -> str:
        """
        Generate the pseudo-random bit-string from `seed`
        :param seed: uniformly sampled seed
        :type seed: int
        """
        totalLen = self.expansion_factor
        prgbitString = ''
        if seed < (self.prime_field-1)//2:
            msb = 0
        else:
            msb = 1
        prgbitString = prgbitString+str(msb)
        i = 1
        while i < totalLen:
            i = i+1
            seed = pow(self.generator, seed, self.prime_field)
            if seed < (self.prime_field-1)//2:
                msb = 0
            else:
                msb = 1
            prgbitString = prgbitString+str(msb)
        return prgbitString
        pass
