import Cryptodome.Util.number
import Cryptodome.Random


class Rabin:
    bits = 0

    # default constructor
    def __init__(self, bits):
        self.bits = bits

    def __generate_prime_number(self):
        while True:
            prime_number = Cryptodome.Util.number.getPrime(self.bits, randfunc=Cryptodome.Random.get_random_bytes)
            if (prime_number % 4) == 3:
                break
        return prime_number

    def encrypt(self):
        print("encrypt")

    def decrypt(self):
        print("decrypt")

    def generate_key(self):
        p = self.__generate_prime_number()
        q = self.__generate_prime_number()
        if p == q:
            raise Exception("Numbers cannot be same!")
        n = p * q
        return n, (p, q)


if __name__ == '__main__':
    rabin = Rabin(60)
    key = rabin.generate_key()
    print(key)
