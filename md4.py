import struct
import sys

class MD4:
    width = 32
    mask =  0xFFFFFFFF
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def __init__(self, message: bytes | None = None):
        self.message = message if message else b""

        m1 = len(self.message) * 8
        self.message+= b"\x80"
        self.message += b"\x00" * (-(len(self.message)+8)%64)

        self.message += struct.pack('<Q',m1)

        self._process([self.message[i:i+64] for i in range(0,len(self.message),64)])
    
    def __str__(self):
        return self.hexdigest()
    
    def __eq__(self, value: object) -> bool:
        return self.h == value.h
    
    def bytes(self):
        return struct.pack('<4L',*self.h)
    
    def hexbytes(self):
        return self.hexdigest().encode()
    
    def hexdigest(self):
        return "".join(f"{value:02x}" for value in self.bytes())
    
    def _process(self,chunks):
        for chunk in chunks:
            X, h = list(struct.unpack("<16I",chunk)),self.h.copy()

            # Round 1
            Xi = [3,7,11,19]
            for n in range(16):
                i,j,k,l = map(lambda x: x%4,range(-n,-n+4))
                K,S = n,Xi[n%4]

                hn = h[i] + MD4.F(h[j],h[k],h[l])+ X[K]

                h[i] = MD4.lrot(hn & MD4.mask,S)

            #Round 2
            Xi = [3,5,9,13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.lrot(hn & MD4.mask, S)
            
            #Round 3

            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.lrot(hn & MD4.mask, S)
            
            self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]
    
    @staticmethod
    def F(x,y,z):
        return (x&y) | (~x & z)
    
    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z
    
    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits
    

def main():
    if len(sys.argv) > 1:
        messages = [msg.encode() for msg in sys.argv[1:]]
        print('Actual hashes:')
        for message in messages:
            print(MD4(message))
    else:
        messages = [b"",b"Hello world",b"Hi, my dear friend"]
        known_hashes = [
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "2f34e7edc8180b87578159ff58e87c1a",
            "44179e75a717f84cbdc8343fed7cd33b"
        ]

        for message, expected in zip(messages,known_hashes):
            print(f'Message:{message}\nExpected hash:{expected}\nActual hash:{MD4(message)}')


if __name__ == '__main__':
    main()