import Cryptodome.Util.number
import Cryptodome.Random


class Rabin:
    __bits = 0
    __public_key = 0
    __private_key = 0
    __message = ""

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
        """
        Generiranje velikih prim brojeva.
        :return:
        :rtype:
        """
        while True:
            prime_number = Cryptodome.Util.number.getPrime(self.__bits)
            if (prime_number % 4) == 3:
                break
        return prime_number

    def __convert_message(self, message):
        """
        Konvertira poruku u bit string (binarni) i dodaje zadnjih 6 bitova na kraj (zalihost).
        :param message:
        :type message: string ili int
        :return: int_output
        :rtype: int
        """
        converted = self.__convert_by_type(message)
        bit_string = bin(converted)  # convert to a bit string
        output = bit_string + bit_string[-6:]  # pad the last 6 bits to the end
        int_output = int(output, 2)  # convert back to integer
        return int_output

    def __extended_euclidean(self, a, b):
        """

        :param a:
        :type a:
        :param b:
        :type b:
        :return:
        :rtype:
        """
        if a == 0:
            return b, 0, 1
        else:
            gcd, y, x = self.__extended_euclidean(b % a, a)
            return gcd, x - (b // a) * y, y

    @staticmethod
    def __convert_by_type(message):
        """
        Za sada se provjerava samo da li je string i napravi konverzija, inače ako je int vrati poruku kakva jest.
        :param message:
        :type message:
        :return:
        :rtype:
        """
        if isinstance(message, str):
            message = Cryptodome.Util.number.bytes_to_long(message.encode('utf-8'))
        else:
            message = message
        return message

    @staticmethod
    def __select_solution(solutions):
        """
        Odabir između 4 moguća rješenja.
        :param solutions:
        :type solutions:
        :return:
        :rtype:
        """
        for i in solutions:
            binary = bin(i)
            append = binary[-6:]  # take the last 6 bits
            binary = binary[:-6]  # remove the last 6 bits

            if append == binary[-6:]:
                return i
        return

    def generate_key(self):
        """
        Generiranje javnog i privatnog ključa.
        :return:
        :rtype:
        """
        p = self.__generate_prime_number()
        q = self.__generate_prime_number()
        if p == q: #prosti brojevi ne smiju biti isti 
            print(p, q, "Numbers cannot be same! Generating again...")
            return self.generate_key()
        elif p % 4 != 3 | q % 4 != 3: #prosti brojevi moraju biti kongruentni s 3(mod4)
            print(p, q, "Numbers cannot be same! Generating again...")
            return self.generate_key()
        n = p * q
        self.set_public_key(n)
        self.set_private_key((p, q))

    def encrypt(self, message):
        """
        Enkripcija
        :param message:
        :type message:
        :return:
        :rtype:
        """
        self.__message = message
        message = self.__convert_message(message)
        return pow(message, 2, self.get_public_key())

    def decrypt(self, cipher):
        """
        Dekripcija
        :param cipher:
        :type cipher:
        :return:
        :rtype:
        """
        n = self.get_public_key()
        p = self.get_private_key()[0]
        q = self.get_private_key()[1]

        r = pow(cipher, (p + 1) // 4, p)
        s = pow(cipher, (q + 1) // 4, q)

        ext = self.__extended_euclidean(p, q)
        a = ext[1]
        b = ext[2]

        # x = (aps + bqr)(mod n)
        # y = (aps - bqr)(mod n)
        x = ((a * p * s + b * q * r) % n)
        y = ((a * p * s - b * q * r) % n)

        solutions = [x, n - x, y, n - y]
        print("Possible solutions:", solutions)

        plain_text = self.__select_solution(solutions)

        string = bin(plain_text)
        string = string[:-6]
        plain_text = int(string, 2)

        decrypted_text = self.__get_decrypted_text(plain_text)

        return decrypted_text

    def __get_decrypted_text(self, plain_text):
        """

        :param plain_text:
        :type plain_text:
        :return:
        :rtype:
        """
        if isinstance(self.__message, str):
            formatted_text = format(plain_text, 'x')
            text_decrypted = bytes.fromhex(formatted_text).decode()
        else:
            text_decrypted = plain_text
        return text_decrypted


if __name__ == '__main__':
    rabin = Rabin(512)
    rabin.generate_key()

    print("Public key:", rabin.get_public_key())
    print("Private key:", rabin.get_private_key())
    print("\n")

    text = "Ovo je otvoreni tekst!"
    print("Unjeli smo otvoreni tekst: ", text)
    cipher_text_string = rabin.encrypt(text)
    print("Cipher text string:", cipher_text_string)
    decrypted_text_string = rabin.decrypt(cipher_text_string)
    print("Decrypted text string:", decrypted_text_string)
    print("\n")

    cipher_text_int = rabin.encrypt(123456789)
    print("Cipher text int:", cipher_text_int)
    decrypted_text_int = rabin.decrypt(cipher_text_int)
    print("Decrypted text int:", decrypted_text_int)
