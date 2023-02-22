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
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.key = key
        pass

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        binarySeedValue = bin(x)[2:]
        binarySeedValue = binarySeedValue.zfill(self.security_parameter)
        length = len(binarySeedValue)
        seedValue = self.key
        i = 0
        while i < length:
            msbBit = binarySeedValue[i]
            i = i+1
            prg = PRG(self.security_parameter,
                      self.generator, self.prime_field, 2*length)
            newSeed = prg.generate(seedValue)
            if msbBit == '0':
                newSeed = newSeed[0:length]
            else:
                newSeed = newSeed[length:]
            seedValue = int(newSeed, 2)
        return seedValue
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
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.seed = seed
        pass

    def mac(self, message: str, random_identifier: int) -> str:
        """
        Generate tag t
        :param random_identifier: r
        :type random_identifier: int
        :param message: message encoded as bit-string
        :type message: str
        """
        prf = PRF(self.security_parameter, self.generator,
                  self.prime_field, self.seed)
        blockSize = self.security_parameter//4
        totalBlock = len(message)//blockSize
        if (blockSize*totalBlock) != len(message):
            rem = len(message) % blockSize
            totalAppendedBit = blockSize-rem
            message = message+"1"+"0"*(totalAppendedBit-1)
            print("hello", message)
        totalBlock = len(message)//blockSize
        i = 1
        output = ''
        random_identifier = bin(random_identifier)[2:].zfill(blockSize)
        totalBlockInbin = bin(totalBlock)[2:].zfill(blockSize)
        firstidx = 0
        while i <= totalBlock:
            temp = random_identifier+totalBlockInbin
            temp = temp+bin(i)[2:].zfill(blockSize)
            temp = temp+message[firstidx:firstidx+blockSize]
            firstidx += blockSize
            i = i+1
            value = int(temp, 2)
            prfoutput = bin(prf.evaluate(value))[
                2:].zfill(self.security_parameter)
            output += prfoutput
        macOut = random_identifier+output
        return macOut
        pass

    def vrfy(self, message: str, tag: str) -> bool:
        """
        Verify whether the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        random_identifier = tag[0:self.security_parameter//4:1]
        random_identifier = int(random_identifier, 2)
        rcvdtag = self.mac(message, random_identifier)
        if rcvdtag == tag:
            return True
        else:
            return False
        pass
