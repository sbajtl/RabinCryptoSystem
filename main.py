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

    def __generate_prime_number(self):
        while True:
            prime_number = Cryptodome.Util.number.getPrime(self.__bits, randfunc=Cryptodome.Random.get_random_bytes)
            if (prime_number % 4) == 3:
                break
        return prime_number

    @staticmethod
    def __convert_message_to_int(message):

        # byte_array = Cryptodome.Util.number.bytes_to_long(message.encode('utf-8'))  #message.encode()
        # # binary_int = int.from_bytes(byte_array, "big")
        # binary_string = bin(byte_array)  # convert to a bit string
        # output = binary_string + binary_string[-6:]  # pad the last 16 bits to the end
        # int_output = int(output, 2)  # convert back to integer

        binary_str = bin(message)  # convert to a bit string
        output = binary_str + binary_str[-6:]  # pad the last 16 bits to the end
        return int(output, 2)  # convert back to integer

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
        q = message ** 2
        enc = q % self.get_public_key()
        return enc

    def decrypt(self, cipher):
        n = self.get_public_key()
        p = self.get_private_key()[0]
        q = self.get_private_key()[1]

        r = pow(cipher, (p + 1) // 4, p)
        # p2 = p - p1

        s = pow(cipher, (q + 1) // 4, q)
        # q2 = q - q1

        ext = self.egcd(p, q)
        a = ext[1]
        b = ext[2]

        # x = (aps + bqr)(mod n)
        # y = (aps - bqr)(mod n)
        x = ((a * p * s + b * q * r) % n)
        y = ((a * p * s - b * q * r) % n)

        lst = [x, n - x, y, n - y]
        print(lst)

        plaintext = self.__choose(lst)

        string = bin(plaintext)
        string = string[:-6]
        plaintext = int(string, 2)

        return plaintext

    # decide which answer to choose
    @staticmethod
    def __choose(lst):

        for i in lst:
            binary = bin(i)
            append = binary[-6:]  # take the last 16 bits
            binary = binary[:-6]  # remove the last 16 bits
            if append == binary[-6:]:
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
    rabin = Rabin(20)
    rabin.generate_key()

    print("Public key: ", rabin.get_public_key())
    print("Private key: ", rabin.get_private_key())

    cipher_text = rabin.encrypt(666666)

    print("Cipher text: ", cipher_text)
    decrypted = rabin.decrypt(cipher_text)
    print("DECRIPTED", decrypted)

    # st = format(decrypted, 'x')
    # st2 = format(decrypted, 'x')
    # print("Decripted text: ", bytes.fromhex(st).decode())
    # print("Decripted2 text: ", bytes.fromhex(st2).decode())
