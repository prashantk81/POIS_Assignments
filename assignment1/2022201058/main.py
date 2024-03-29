from A1.PRG.PRG import *
from A1.PRF.PRF import *
from A1.CBC_MAC.CBC_MAC import *
from A1.MAC.MAC import *
from A1.EAV.EAV import *
from A1.CCA.CCA import *
from A1.CPA.CPA import *


if __name__ == "__main__":

    # print("CPA with ofb")
    # CPAobj = CPA(4, 307, 112, 58, "OFB")
    # enc = CPAobj.enc("1010100011100111", 4)
    # print("Encryption Msg-> ", enc)
    # print("Decrypt msg", CPAobj.dec(enc))
    # CPAobj = CPA(5, 599, 189, 145, "OFB")
    # enc = CPAobj.enc("11100011011110010111", 7)
    # print("Encryption Msg-> ", enc)
    # print("Decrypt msg", CPAobj.dec(enc))
    # CPAobj = CPA(6, 881, 217, 113, "OFB")
    # enc = CPAobj.enc("101011011101", 5)
    # print("Encryption Msg-> ", enc)
    # print("Decrypt msg", CPAobj.dec(enc))
    # CPAobj = CPA(6, 59, 14, 10, "OFB")
    # enc = CPAobj.enc("111000101010", 37)
    # print("Encryption Msg-> ", enc)
    # print("Decrypt msg", CPAobj.dec(enc))
    # CPAobj = CPA(8, 11, 3, 15, "OFB")
    # enc = CPAobj.enc("1010100110110111", 8)
    # print("Encryption Msg-> ", enc)
    # print("Decrypt msg", CPAobj.dec(enc))

    print("CPA with cbc")
    CPAobj = CPA(4, 307, 112, 58, "CBC")
    enc = CPAobj.enc("1010100011100111", 4)
    print("Encryption Msg-> ", enc)
    print("Decrypt msg", CPAobj.dec(enc))
    CPAobj = CPA(5, 599, 189, 145, "CBC")
    enc = CPAobj.enc("11100011011110010111", 7)
    print("Encryption Msg-> ", enc)
    print("Decrypt msg", CPAobj.dec(enc))
    CPAobj = CPA(6, 881, 217, 113, "CBC")
    enc = CPAobj.enc("101011011101", 5)
    print("Encryption Msg-> ", enc)
    print("Decrypt msg", CPAobj.dec(enc))
    CPAobj = CPA(6, 59, 14, 10, "CBC")
    enc = CPAobj.enc("111000101010", 37)
    print("Encryption Msg-> ", enc)
    print("Decrypt msg", CPAobj.dec(enc))
    CPAobj = CPA(8, 11, 3, 15, "CBC")
    enc = CPAobj.enc("1010100110110111", 8)
    print("Encryption Msg-> ", enc)
    print("Decrypt msg", CPAobj.dec(enc))

    # print("Pseudo Random Gererator")
    # PRGobj = PRG(7, 13, 41, 10)
    # print(PRGobj.generate(17))
    # PRGobj = PRG(9, 4, 11, 12)
    # print(PRGobj.generate(35))
    # PRGobj = PRG(7, 7, 17, 11)
    # print(PRGobj.generate(125))
    # PRGobj = PRG(9, 35, 97, 20)
    # print(PRGobj.generate(263))
    # PRGobj = PRG(12, 11, 29, 33)
    # print(PRGobj.generate(1058))

    # print("Pseudo Random Function")
    # PRFobj = PRF(8, 36, 191, 150)
    # print(PRFobj.evaluate(190))
    # PRFobj = PRF(8, 45, 137, 129)
    # print(PRFobj.evaluate(201))
    # PRFobj = PRF(10, 71, 179, 568)
    # print(PRFobj.evaluate(890))
    # PRFobj = PRF(11, 44, 107, 1056)
    # print(PRFobj.evaluate(1300))
    # PRFobj = PRF(12, 14, 79, 1389)
    # print(PRFobj.evaluate(1780))

    # print("Encryption Scheme against Eavesdropping Adversary")
    # EAVESobj = Eavesdrop(7, 16, 7, 21, 59)
    # cipherMessage = EAVESobj.enc("1000101")
    # print("cipher text-> ", cipherMessage)
    # print("plain text-> ", EAVESobj.dec(cipherMessage))
    # EAVESobj = Eavesdrop(8, 19, 8, 28, 163)
    # cipherMessage = EAVESobj.enc("10101001")
    # print("cipher text-> ", cipherMessage)
    # print("plain text-> ", EAVESobj.dec(cipherMessage))
    # EAVESobj = Eavesdrop(8, 156, 8, 71, 599)
    # cipherMessage = EAVESobj.enc("10101001")
    # print("cipher text-> ", cipherMessage)
    # print("plain text-> ", EAVESobj.dec(cipherMessage))
    # EAVESobj = Eavesdrop(10, 312, 10, 213, 719)
    # cipherMessage = EAVESobj.enc("1010110010")
    # print("cipher text-> ", cipherMessage)
    # print("plain text-> ", EAVESobj.dec(cipherMessage))
    # EAVESobj = Eavesdrop(10, 112, 10, 259, 881)
    # cipherMessage = EAVESobj.enc("1010110010")
    # print("cipher text-> ", cipherMessage)
    # print("plain text-> ", EAVESobj.dec(cipherMessage))

    # print("MAC")
    # MACobj = MAC(16, 499, 145, 179)
    # m = "100001011111"
    # tags = MACobj.mac(m, 13)
    # print("tag->", tags)
    # print("Mac verification", MACobj.vrfy(m, tags))
    # MACobj = MAC(12, 107, 39, 120)
    # m = "110101"
    # tags = MACobj.mac(m, 2)
    # print("tag->", tags)
    # print("Mac verification", MACobj.vrfy(m, tags))
    # MACobj = MAC(20, 137, 45, 87)
    # m = "010011001000110"
    # tags = MACobj.mac(m, 7)
    # print("tag->", tags)
    # print("Mac verification", MACobj.vrfy(m, tags))
    # MACobj = MAC(24, 827, 127, 400)
    # m = "101100101000101000101111"
    # tags = MACobj.mac(m, 8)
    # print("tag->", tags)
    # print("Mac verification", MACobj.vrfy(m, tags))
    # MACobj = MAC(28, 617, 150, 123)
    # m = "111011101100101001110"
    # tags = MACobj.mac(m, 2)
    # print("tag->", tags)
    # print("Mac verification", MACobj.vrfy(m, tags))

    # print(CBC_MAC)
    # CBCMACobj = CBC_MAC(4, 35, 97, [14, 12])
    # x = CBCMACobj.mac("1010100101111")
    # print(x)
    # print("Verification-> ", CBCMACobj.vrfy("1010100101111", x))
    # CBCMACobj = CBC_MAC(4, 144, 719, [11, 8])
    # x = CBCMACobj.mac("11011101011000111000")
    # print(x)
    # print("Verification-> ", CBCMACobj.vrfy("11011101011000111000", x))
    # CBCMACobj = CBC_MAC(4, 67, 461, [5, 6])
    # x = CBCMACobj.mac("11100111")
    # print(x)
    # print("Verification-> ", CBCMACobj.vrfy("11100111", x))
    # CBCMACobj = CBC_MAC(4, 113, 227, [2, 7])
    # x = CBCMACobj.mac("111010100101")
    # print(x)
    # print("Verification-> ", CBCMACobj.vrfy("111010100101", x))
    # CBCMACobj = CBC_MAC(4, 139, 541, [9, 11])
    # x = CBCMACobj.mac("1010111011010110")
    # print(x)
    # print("Verification-> ", CBCMACobj.vrfy("1010111011010110", x))

    # print("CPA with ctr")
    # CPAobj = CPA(4, 307, 112, 58, "CTR")
    # enc = CPAobj.enc("1010100011100111", 4)
    # print("Encryption Msg-> ", enc)
    # print("Decrypt msg", CPAobj.dec(enc))
    # CPAobj = CPA(5, 599, 189, 145, "CTR")
    # enc = CPAobj.enc("11100011011110010111", 7)
    # print("Encryption Msg-> ", enc)
    # print("Decrypt msg", CPAobj.dec(enc))
    # CPAobj = CPA(6, 881, 217, 113, "CTR")
    # enc = CPAobj.enc("101011011101", 5)
    # print("Encryption Msg-> ", enc)
    # print("Decrypt msg", CPAobj.dec(enc))
    # CPAobj = CPA(6, 59, 14, 10, "CTR")
    # enc = CPAobj.enc("111000101010", 37)
    # print("Encryption Msg-> ", enc)
    # print("Decrypt msg", CPAobj.dec(enc))
    # CPAobj = CPA(8, 11, 3, 15, "CTR")
    # enc = CPAobj.enc("1010100110110111", 8)
    # print("Encryption Msg-> ", enc)
    # print("Decrypt msg", CPAobj.dec(enc))

    # print("CCA")
    # CCAobj = CCA(7, 41, 17, 34, [10, 9], "CTR")
    # x = CCAobj.enc("101110101011101000011", 12)
    # print("Encrypt msg-> ", x)
    # print("decrypt msg-> ", CCAobj.dec(x))
    # CCAobj = CCA(9, 149, 45, 41, [11, 23], "CTR")
    # x = CCAobj.enc("010011110000100110101110001100000010010000111", 10)
    # print("Encrypt msg-> ", x)
    # print("decrypt msg-> ", CCAobj.dec(x))
    # CCAobj = CCA(6, 17, 7, 5, [17, 3], "CTR")
    # x = CCAobj.enc("000101001000110010100110000000010100", 18)
    # print("Encrypt msg-> ", x)
    # print("decrypt msg-> ", CCAobj.dec(x))
    # CCAobj = CCA(10, 269, 65, 52, [64, 43], "CTR")
    # x = CCAobj.enc(
    #     "011001111000011100111010000010110110100100111100101011000010", 150)
    # print("Encrypt msg-> ", x)
    # print("decrypt msg-> ", CCAobj.dec(x))
    # CCAobj = CCA(8, 127, 55, 34, [56, 17], "CTR")
    # x = CCAobj.enc(
    #     "111101000100001110100010011101001111010101001111", 100)
    # print("Encrypt msg-> ", x)
    # print("decrypt msg-> ", CCAobj.dec(x))
