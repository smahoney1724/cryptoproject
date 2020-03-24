plaintext = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
test_text = b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34'
key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0D\x0e\x0f'
test_key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
Nb = 4
Nk = 4
Nr = 10
blocksize = 16
from copy import copy

sub_box = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

rcon =   [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
          0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
          0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
          0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39]

gfield =[[0x02,0x03,0x01,0x01],
         [0x01,0x02,0x03,0x01],
         [0x01,0x01,0x02,0x03],
         [0x03,0x01,0x01,0x02]]

results =[[0x00,0x00,0x00,0x00],
         [0x00,0x00,0x00,0x00],
         [0x00,0x00,0x00,0x00],
         [0x00,0x00,0x00,0x00]]

def main():
    round_keys = KeyExpansion(key)
    print(len(round_keys))
    print(round_keys)
    encrypt(plaintext,round_keys)

def statetransform(plaintext):
    return [list(plaintext[i:i+4]) for i in range(0, len(plaintext),Nb)]

def stringtransform(state):
    string = list(sum(state,[]))
    return str(hex(string[0]) + " " + hex(string[1]) + " " + hex(string[2]) + " " + hex(string[3])
          + " " + hex(string[4]) + " " + hex(string[5]) + " " + hex(string[6]) + " " + hex(string[7])
          + " " + hex(string[8]) + " " + hex(string[9]) + " " + hex(string[10]) + " " + hex(string[11])
          + " " + hex(string[12]) + " " + hex(string[13]) + " " + hex(string[14]) + " " + hex(string[15]))

def SubBytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = sub_box[state[r][c]]

def ShiftRows(state):
    # 2nd row
    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    #3rd row
    state[0][ 2], state[1][ 2], state[2][ 2], state[3][ 2] = state[2][ 2], state[3][ 2], state[0][ 2], state[1][ 2]
    #4th row
    state[0][ 3], state[1][ 3], state[2][ 3], state[3][ 3] = state[3][ 3], state[0][ 3], state[1][ 3], state[2][ 3]
def gmult(x,y):
    p = 0
    bit = 0
    for i in range(8):
        if x & 1 == 1:
            p ^= y
        bit = y & 0x80
        y <<= 1
        if bit == 0x80:
            y ^= 0x1b
        x >>= 1
    return p % 256


def MixColumn(col):
    temp = copy(col)
    col[0] = gmult(gfield[0][0], temp[0]) ^ gmult(gfield[0][1], temp[1]) ^ gmult(gfield[0][2], temp[2]) ^ gmult(gfield[0][3], temp[3])
    col[1] = gmult(gfield[1][0], temp[0]) ^ gmult(gfield[1][1], temp[1]) ^ gmult(gfield[1][2], temp[2]) ^ gmult(gfield[1][3], temp[3])
    col[2] = gmult(gfield[2][0], temp[0]) ^ gmult(gfield[2][1], temp[1]) ^ gmult(gfield[2][2], temp[2]) ^ gmult(gfield[2][3], temp[3])
    col[3] = gmult(gfield[3][0], temp[0]) ^ gmult(gfield[3][1], temp[1]) ^ gmult(gfield[3][2], temp[2]) ^ gmult(gfield[3][3], temp[3])


def MixColumns(state):
    for i in range(4):
        MixColumn(state[i])

def KeyExpansion(key):
    key_matrix = statetransform(key)
    i = Nk
    while( i < (Nb * (Nr +1))):
        temp = list(key_matrix[-1])  # previous word
        if(i % Nk == 0):
            # rot and sub then bitwise xor with rcon table
            RotWord(temp)
            temp = SubWord(temp)
            # rcon = {x,0,0,0}
            temp[0] ^= rcon[int(i/4)]
        i = i + 1
        temp = xor_word(temp, key_matrix[-4])
        key_matrix.append(temp)

    return key_matrix

def xor_word(word, word2):
    temp = word
    temp[0] = word[0] ^ word2[0]
    temp[1] = word[1] ^ word2[1]
    temp[2] = word[2] ^ word2[2]
    temp[3] = word[3] ^ word2[3]
    return temp

def SubWord(word):
    word = [sub_box[x] for x in word]
    return word

def RotWord(word):
    #ROT
    word.append(word.pop(0))

def AddRoundKey(state, round_key):
    #bitwise xor each column with column from key
    #columns
    for i in range(4):
        #rows
        for j in range(4):
            state[i][j] ^= round_key[i][j]



def encrypt(message,round_keys):
    state = statetransform(message)
    print("Round[0] Input = {0}".format(stringtransform(state)))
    AddRoundKey(state,round_keys[0:4])
    print("Round[0] Key Sch = {0}".format(stringtransform(round_keys[0:4])))
    #128 bits 10 rounds
    for i in range(1, 10):
        print("Round[{0}] Start state = {1}".format(i, stringtransform(state)))
        SubBytes(state)
        print("Round[{0}] SubBytes state = {1}".format(i, stringtransform(state)))
        ShiftRows(state)
        print("Round[{0}] ShiftRows state = {1}".format(i, stringtransform(state)))
        MixColumns(state)
        print("Round[{0}] MixColumns state = {1}".format(i, stringtransform(state)))
        AddRoundKey(state, round_keys[(i*4):(i*4+4)])
        print("Round[{0}] Key Sch = {1}".format(i, stringtransform(round_keys[(i*4):(i*4+4)])))

    print("Round[{0}] Start state = {1}".format(i+1, stringtransform(state)))
    SubBytes(state)
    print("Round[{0}] SubBytes state = {1}".format(i+1, stringtransform(state)))
    ShiftRows(state)
    print("Round[{0}] ShiftRows state = {1}".format(i+1, stringtransform(state)))
    AddRoundKey(state, round_keys[((i+1) * 4):((i+1) * 4 + 4)])
    print("Round[{0}] Key Sch = {1}".format(i+1, stringtransform(round_keys[((i+1) * 4):((i+1) * 4 + 4)])))
    print("Round[{0}] Output = {1}".format(i + 1, stringtransform(state)))
    return message

main()