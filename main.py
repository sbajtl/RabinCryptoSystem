from decimal import Decimal

import Cryptodome.Util.number
import Cryptodome.Random


class Rabin:
    __bits = 0
    __public_key = None
    __private_key = None

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
        a = 1//4 * self.get_private_key()[0] + 1
        b = cipher ** a
        m_p = b % self.get_private_key()[0]

        c = 1//4 * self.get_private_key()[1] + 1
        d = cipher ** c
        m_q = d % self.get_private_key()[1]
        print("m_p: ", m_p)
        print("m_q: ", m_q)

        test = self.egcd(self.get_private_key()[0], self.get_private_key()[1])

        print("test: ", test)
        # TODO .......... SVE :D

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
    rabin = Rabin(128)
    rabin.generate_key()
    print("Public key: ", rabin.get_public_key())
    print("Private key: ", rabin.get_private_key())

    cipher_text = rabin.encrypt('Pokušaj testiranje ili vateva')
    print("Cipher text: ", cipher_text)
    rabin.decrypt(cipher_text)
