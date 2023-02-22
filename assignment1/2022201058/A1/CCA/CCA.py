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


class CPA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key: int, mode="CTR"):
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
        :param mode: Block-Cipher mode of operation
            - CTR
            - OFB
            - CBC
        :type mode: str
        """
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.key = key
        self.mode = mode
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

    def enc(self, message: str, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack using randomized ctr mode
        :param message: m
        :type message: int
        :param random_seed: ctr
        :type random_seed: int
        """
        if (self.mode == "CTR"):
            prf = PRF(self.security_parameter, self.generator,
                      self.prime_field, self.key)
            blockSize = self.security_parameter
            totalBlocks = len(message)//blockSize
            if (blockSize*totalBlocks) != len(message):
                rem = len(message) % blockSize
                totalAppendedBit = blockSize-rem
                message = message+"1"+"0"*(totalAppendedBit-1)
            totalBlocks = len(message)//blockSize
            i = 1
            cpaOutput = ''
            count = 1
            msgblock = 0
            while i <= totalBlocks:
                prfoutput = prf.evaluate(random_seed+count)
                count += 1
                prfoutput = bin(prfoutput)[2:].zfill(self.security_parameter)
                exorOutput = self.exor(
                    prfoutput, message[msgblock:msgblock+self.security_parameter])
                msgblock += self.security_parameter
                cpaOutput += exorOutput
                i = i+1
            finalOutput = bin(random_seed)[2:].zfill(
                self.security_parameter)+cpaOutput
            return finalOutput
        elif self.mode == "OFB":
            prf = PRF(self.security_parameter, self.generator,
                      self.prime_field, self.key)
            blockSize = self.security_parameter
            totalBlocks = len(message)//blockSize
            if (blockSize*totalBlocks) != len(message):
                rem = len(message) % blockSize
                totalAppendedBit = blockSize-rem
                message = message+"1"+"0"*(totalAppendedBit-1)
            totalBlocks = len(message)//blockSize
            i = 1
            cpaOutput = ''
            msgblock = 0
            rs = random_seed
            while i <= totalBlocks:
                prfoutput = prf.evaluate(random_seed)
                random_seed = prfoutput
                prfoutput = bin(prfoutput)[2:].zfill(self.security_parameter)
                exorOutput = self.exor(
                    prfoutput, message[msgblock:msgblock+self.security_parameter])
                msgblock += self.security_parameter
                cpaOutput += exorOutput
                i = i+1
            finalOutput = bin(rs)[2:].zfill(
                self.security_parameter)+cpaOutput
            return finalOutput
        else:
            self.message = message
            prf = PRF(self.security_parameter, self.generator,
                      self.prime_field, self.key)
            blockSize = self.security_parameter
            totalBlocks = len(message)//blockSize
            if (blockSize*totalBlocks) != len(message):
                rem = len(message) % blockSize
                totalAppendedBit = blockSize-rem
                message = message+"1"+"0"*(totalAppendedBit-1)
            totalBlocks = len(message)//blockSize
            i = 1
            cpaOutput = ''
            msgblock = 0
            rs = random_seed
            random_seed = bin(random_seed)[2:].zfill(self.security_parameter)
            while i <= totalBlocks:
                exorOutput = self.exor(
                    random_seed, message[msgblock:msgblock+self.security_parameter])
                prfoutput = prf.evaluate(int(exorOutput, 2))
                msgblock += self.security_parameter
                temp = bin(prfoutput)[2:].zfill(self.security_parameter)
                random_seed = temp
                cpaOutput += temp
                i = i+1
            finalOutput = bin(rs)[2:].zfill(
                self.security_parameter)+cpaOutput
            return finalOutput

    def dec(self, cipher: str) -> str:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        if self.mode == "CTR":
            random_seed = int(cipher[0:self.security_parameter], 2)
            cipherText = cipher[self.security_parameter:]
            prf = PRF(self.security_parameter, self.generator,
                      self.prime_field, self.key)
            totalBlocks = len(cipherText)//self.security_parameter
            i = 1
            cpaOutput = ''
            count = 1
            msgblock = 0
            while i <= totalBlocks:
                prfoutput = prf.evaluate(random_seed+count)
                count += 1
                prfoutput = bin(prfoutput)[2:].zfill(self.security_parameter)
                exorOutput = self.exor(
                    prfoutput, cipherText[msgblock:msgblock+self.security_parameter])
                msgblock += self.security_parameter
                cpaOutput += exorOutput
                i = i+1

            return cpaOutput
        elif self.mode == "OFB":
            random_seed = int(cipher[0:self.security_parameter], 2)
            cipherText = cipher[self.security_parameter:]
            prf = PRF(self.security_parameter, self.generator,
                      self.prime_field, self.key)
            totalBlocks = len(cipherText)//self.security_parameter
            i = 1
            cpaOutput = ''
            msgblock = 0
            while i <= totalBlocks:
                prfoutput = prf.evaluate(random_seed)
                random_seed = prfoutput
                prfoutput = bin(prfoutput)[2:].zfill(self.security_parameter)
                exorOutput = self.exor(
                    prfoutput, cipherText[msgblock:msgblock+self.security_parameter])
                msgblock += self.security_parameter
                cpaOutput += exorOutput
                i = i+1
            return cpaOutput
        else:
            random_seed = int(cipher[0:self.security_parameter], 2)
            cipherText = cipher[self.security_parameter:]
            prf = PRF(self.security_parameter, self.generator,
                      self.prime_field, self.key)
            totalBlocks = len(cipherText)//self.security_parameter
            i = 1
            cpaOutput = ''
            msgblock = 0
            while i <= totalBlocks:
                prfoutput = prf.evaluate(random_seed)
                exorOutput = self.exor(
                    bin(prfoutput)[2:].zfill(self.security_parameter), cipherText[msgblock:msgblock+self.security_parameter])
                random_seed = int(
                    cipherText[msgblock:msgblock+self.security_parameter], 2)
                msgblock += self.security_parameter
                cpaOutput += exorOutput
                i = i+1

            return self.message


class CCA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key_cpa: int, key_mac: list[int],
                 cpa_mode="CTR"):
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
        :type key_mac: list[int]
        :param cpa_mode: Block-Cipher mode of operation for CPA
            - CTR
            - OFB
            - CBC
        :type cpa_mode: str
        """
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.key_cpa = key_cpa
        self.key_mac = key_mac
        self.cpa_mode = cpa_mode
        pass

    def enc(self, message: str, cpa_random_seed: int) -> str:
        """
        Encrypt message against Chosen Ciphertext Attack
        :param message: m
        :type message: str
        :param cpa_random_seed: random seed for CPA encryption
        :type cpa_random_seed: int
        """
        cpa = CPA(self.security_parameter, self.prime_field,
                  self.generator, self.key_cpa, self.cpa_mode)
        cpaOutput = cpa.enc(message, cpa_random_seed)
        cbcmac = CBC_MAC(self.security_parameter, self.generator,
                         self.prime_field, self.key_mac)
        cbcmacOutput = bin(cbcmac.mac(cpaOutput))[
            2:].zfill(self.security_parameter)
        return cpaOutput+cbcmacOutput
        pass

    def dec(self, cipher: str) -> Optional[str]:
        """
        Decrypt ciphertext to obtain message
        :param cipher: <c, t>
        :type cipher: str
        """
        cipher = cipher[::-1]
        cpaoutput = cipher[0:self.security_parameter]
        cpaoutput = cpaoutput[::-1]
        cipher = cipher[::-1]
        cbcmacOutput = cipher[0:len(cipher)-len(cpaoutput)]
        cbcmac = CBC_MAC(self.security_parameter, self.generator,
                         self.prime_field, self.key_mac)
        cbcmacVerify = cbcmac.vrfy(cbcmacOutput, int(cpaoutput, 2))
        if cbcmacVerify:
            return True
        return False
        pass

# Can we use the variable-length MAC construction in place of CBC_MAC?
# No,We cannot use variable-length MAC constructions in place of CBC-MAC for making secure encryption schemes.
# CBC-MAC has special properties that make it better for this purpose,
# like being deterministic and having "strong unforgeability."
# Variable-length MAC constructions may have unpredictable output
# and be vulnerable to certain attacks.
# So, CBC-MAC is the best choice for making secure encryption schemes.
