from decimal import Decimal

import Cryptodome.Util.number
import Cryptodome.Random


class Rabin:
    __bits = 0
    __public_key = 0
    __private_key = 0

    # default constructor
    def __init__(self, bits):
        self.__bits = bits

    def get_public_key(self):
        return self.__public_key

    def set_public_key(self, k):
        self.__public_key = k

    def get_private_key(self):
        return self.__private_key

    def set_private_key(self, k):
        self.__private_key = k

    # Find SQROOT in Zp where p = 3 mod 4
    @staticmethod
    def __sqrt_p_3_mod_4(a, p):
        r = pow(a, (p + 1) // 4, p)
        return r

    # Find SQROOT in Zp where p = 5 mod 8
    @staticmethod
    def __sqrt_p_5_mod_8(a, p):
        d = pow(a, (p - 1) // 4, p)
        r = 0
        if d == 1:
            r = pow(a, (p + 3) // 8, p)
        elif d == p - 1:
            r = 2 * a * pow(4 * a, (p - 5) // 8, p) % p

        return r

    def __generate_prime_number(self):
        while True:
            prime_number = Cryptodome.Util.number.getPrime(self.__bits, randfunc=Cryptodome.Random.get_random_bytes)
            if (prime_number % 4) == 3:
                break
        return prime_number

    @staticmethod
    def __convert_message_to_int(message):
        byte_array = message.encode()
        binary_int = int.from_bytes(byte_array, "big")
        binary_string = bin(binary_int)  # convert to a bit string
        output = binary_string + binary_string[-16:]  # pad the last 16 bits to the end
        int_output = int(output, 2)  # convert back to integer
        return int_output

    def egcd(self, a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, y, x = self.egcd(b % a, a)
            return gcd, x - (b // a) * y, y

    '''
    A message M can be encrypted by first converting it to a number m<n using a reversible mapping, 
    then computing c=m^2mod n. The ciphertext is c.
    '''
    def encrypt(self, message):
        # c = m^2 mod n
        message = self.__convert_message_to_int(message)
        return message ** 2 % self.get_public_key()

    def decrypt(self, cipher):
        r, s = 0, 0
        p = self.get_private_key()[0]
        q = self.get_private_key()[1]

        if p % 4 == 3:
            r = self.__sqrt_p_3_mod_4(cipher, p)
        elif p % 8 == 5:
            r = self.__sqrt_p_5_mod_8(cipher, p)
        # for q
        if q % 4 == 3:
            s = self.__sqrt_p_3_mod_4(cipher, q)
        elif q % 8 == 5:
            s = self.__sqrt_p_5_mod_8(cipher, q)

        gcd, c, d = self.egcd(p, q)
        n = self.get_public_key()
        x = (r * d * q + s * c * p) % n
        y = (r * d * q - s * c * p) % n
        lst = [x, n - x, y, n - y]
        print(lst)
        plaintext = self.__choose(lst)

        string = bin(plaintext)
        string = string[:-16]
        plaintext = int(string, 2)

        return plaintext

    # decide which answer to choose
    @staticmethod
    def __choose(lst):

        for i in lst:
            binary = bin(i)
            append = binary[-16:]  # take the last 16 bits
            binary = binary[:-16]  # remove the last 16 bits
            if append == binary[-16:]:
                return i
        return

    '''
    The keys for the Rabin crypto system are generated as follows:
    Choose two large distinct prime numbers p and q such that p≡3mod4 and q≡3mod4.
    Compute n=pq.
    Then n is the public key and the pair (p,q) is the private key.
    '''

    def generate_key(self):
        p = self.__generate_prime_number()
        q = self.__generate_prime_number()
        if p == q:
            print(p, q, "Numbers cannot be same! Generating again...")
            return self.generate_key()
        n = p * q
        self.set_public_key(n)
        self.set_private_key((p, q))


if __name__ == '__main__':
    rabin = Rabin(120)
    rabin.generate_key()
    print("Public key: ", rabin.get_public_key())
    print("Private key: ", rabin.get_private_key())

    cipher_text = rabin.encrypt('Pokušaj testiranje ili ...!')
    print("Cipher text: ", cipher_text)
    decrypted = rabin.decrypt(cipher_text)
    st = format(decrypted, 'x')
    print("Decripted text: ", bytes.fromhex(st).decode())
