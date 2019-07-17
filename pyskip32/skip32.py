import struct

FTABLE = (0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4,
          0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
          0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e,
          0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
          0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68,
          0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
          0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19,
          0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
          0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b,
          0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
          0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0,
          0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
          0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69,
          0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
          0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20,
          0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
          0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43,
          0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
          0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa,
          0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
          0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87,
          0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
          0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b,
          0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
          0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0,
          0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
          0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1,
          0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
          0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5,
          0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
          0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3,
          0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46)


def g(key, k, w):
    g1 = 0xFF & (w >> 8)
    g2 = 0xFF & w

    g3 = FTABLE[g2 ^ key[(4*k) % 10]] ^ g1
    g4 = FTABLE[g3 ^ key[(4*k+1) % 10]] ^ g2
    g5 = FTABLE[g4 ^ key[(4*k+2) % 10]] ^ g3
    g6 = FTABLE[g5 ^ key[(4*k+3) % 10]] ^ g4

    return ((g5<<8) + g6)


def skip32(key, buf, encrypt):
    """
    encode buf using skipjack algorithm
    NOTE: modifies buf, which must be a bytearray of length 4
    """
    assert len(key) >= 10, "key must contain at least 10 bytes (got {})".format(len(key))
    assert type(buf) is bytearray, "buf must be a bytearray (got {})".format(type(buf))
    assert len(buf) == 4, "buf must be exactly 4 bytes (got {})".format(len(buf))

    # sort out direction
    if encrypt:
        kstep, k = 1, 0
    else:
        kstep, k = -1, 23

    # pack into words
    wl = (buf[0] << 8) + buf[1];
    wr = (buf[2] << 8) + buf[3];

    # 24 feistel rounds, doubled up
    for _ in range(12):
        wr ^= g(key, k, wl) ^ k;
        k += kstep;
        wl ^= g(key, k, wr) ^ k;
        k += kstep;

    # implicitly swap halves while unpacking
    buf[0] = wr >> 8;   buf[1] = wr & 0xFF;
    buf[2] = wl >> 8;   buf[3] = wl & 0xFF;


class Skip32:
    """convienence wrapper for for skip32 method that holds key and takes/returns ints"""
    def __init__(self, key):
        # TODO: raise ValueError instead of asserting?
        assert len(key) == 10, "key should be exactly 10 bytes (got {})".format(len(key))
        assert all(type(b) is int and b >= 0x00 and b <= 0xff for b in key), "key must contain only ints in range 0 to 255"
        self._key = key

    def encrypt(self, value):
        # pack should raise if the int doesn't fit in 32 bits
        buf = bytearray(struct.pack(">I", value))
        skip32(self._key, buf, True)
        return struct.unpack(">I", buf)[0]

    def decrypt(self, value):
        buf = bytearray(struct.pack(">I", value))
        skip32(self._key, buf, False)
        return struct.unpack(">I", buf)[0]


if __name__ == "__main__":
    import sys, random, time

    # ensure the encryption algorithm produces expected value for a wellknown key
    # These are the default test values from the original skip32.c
    # BYTE        in[4] = { 0x33,0x22,0x11,0x00 };
    # BYTE        key[10] = { 0x00,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11 };
    wellknown_key = bytearray([ 0x00,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11 ])
    wellknown_clear = int("33221100", 16)
    wellknown_encrypted = int("819d5f1f", 16)
    cipher = Skip32(wellknown_key)
    test_encrypted = cipher.encrypt(wellknown_clear)
    assert test_encrypted == wellknown_encrypted, 'wellknown encryption failed {} => {} != {}'.format(wellknown_clear, test_encrypted, wellknown_encrypted)
    test_decrypted = cipher.decrypt(test_encrypted)
    assert test_decrypted == wellknown_clear, 'wellknown decryption failed {} => {} != {}'.format(test_encrypted, test_decrypted, wellknown_clear)
    sys.stdout.write("wellknown key and value encrypted as expected: {:X} => {:X} => {:X}\n".format(wellknown_clear, test_encrypted, test_decrypted))

    # run some performance tests
    time_ns = getattr(time, 'time_ns', lambda: time.time() * 10e9)
    n = len(sys.argv) == 2 and int(sys.argv[1]) or 15000
    clear = [random.getrandbits(32) for _ in range(n)]
    sys.stdout.write('encrypting/decrypting {} random numbers (should take around 1 second on common harware)\n'.format(len(clear)))
    tstart = time_ns()
    encrypted = [cipher.encrypt(c) for c in clear]
    tencrypt = time_ns()
    decrypted = [cipher.decrypt(d) for d in encrypted]
    tdecrypt = time_ns()
    encrypt_elapsed = (tencrypt - tstart) / 10e9
    decrypt_elapsed = ((tdecrypt - tencrypt) / 10e9)
    sys.stdout.write('encrypt: {} ops/second\n'.format(int(n / encrypt_elapsed)))
    sys.stdout.write('decrypt: {} ops/second\n'.format(int(n / decrypt_elapsed)))
    for i, c in enumerate(clear):
        assert c == decrypted[i], 'value {} failed to decrypt to itself'.format(c)
        if c == encrypted[i]:
            sys.stdout.write('value {} encrypted to itself\n'.format(c))
