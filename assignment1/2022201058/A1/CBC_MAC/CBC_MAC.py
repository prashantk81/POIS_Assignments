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


class CBC_MAC:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, keys: list[int]):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: q
        :type prime_field: int
        :param keys: k₁, k₂
        :type keys: list[int]
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.keys = keys
        pass

    def exor(self, msg1: str, msg2: str) -> str:
        exorAns = ''
        idx = len(msg1)-1
        while idx >= 0:
            if msg1[idx] == msg2[idx]:
                exorAns = '0'+exorAns
            else:
                exorAns = '1'+exorAns
            idx = idx-1
        return exorAns

    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: message encoded as bit-string m
        :type message: str
        """
        key1 = self.keys[0]
        key2 = self.keys[1]
        blockSize = self.security_parameter
        i = 1
        IV = bin(0)[2:].zfill(blockSize)
        totalBlock = len(message)//blockSize
        if (blockSize*totalBlock) != len(message):
            rem = len(message) % blockSize
            totalAppendedBit = blockSize-rem
            message = message+"1"+"0"*(totalAppendedBit-1)
            # print("hello", message)
        totalBlock = len(message)//blockSize
        index = 0
        while i <= totalBlock:
            msgPart = message[index: index+blockSize:1]
            index += blockSize
            exorValue = self.exor(msgPart, IV)
            prf = PRF(self.security_parameter, self.generator,
                      self.prime_field, key1)
            prfoutput = prf.evaluate(int(exorValue, 2))
            IV = bin(prfoutput)[2:]
            IV = IV.zfill(blockSize)
            i = i+1
        # for last msg part
        prf = PRF(self.security_parameter, self.generator,
                  self.prime_field, key2)
        prfoutput = prf.evaluate(int(IV, 2))
        return prfoutput
        pass

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        rcvdmsg = self.mac(message)
        if rcvdmsg == tag:
            return True
        return False
