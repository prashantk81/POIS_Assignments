import secrets
import hmac
import hashlib


def byte_len(y):
 if y==0: return 1
 return (y.bit_length()+7) //8
 
def F(k,x):
    
 hmac_key=k.to_bytes(byte_len(k),'little')
 h=hmac.new(hmac_key,x.to_bytes(32,'little'),hashlib.sha256)
 return h.hexdigest()

def enc(key,data):
    r=secrets.randbits(data.bit_length())
    return r,dec(key,r,data)


def dec(key,r,ciphertext):
    keystream = F(key,r)
    return int(keystream,16) ^ ciphertext

    


if __name__ == "__main__":
    key=secrets.randbits(256)
    msg=1<<255 # is nothing but 2^256
    r,c=enc(key,msg)
    print("cipher text is ",c)

    assert(dec(key,r,c))==msg