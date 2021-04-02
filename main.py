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
        Generiranje velikih prim brojeva. Petlja se vrti dokle god se ne generira prim broj
        koji mora odgovarati uvjetu kongruencije. Time se petlja prekida i vraća prim broj.
        :return: prime_number
        :rtype: int
        """
        while True:
            prime_number = Cryptodome.Util.number.getPrime(self.__bits)
            if (prime_number % 4) == 3:
                break
        return prime_number

    def __convert_message(self, message):
        """
        Konvertira poruku u bit string (binarni) i dodaje zadnjih 6 bitova na kraj (zalihost),
        te se string ponovno pretvara u int.
        :param message:
        :type message: string ili int
        :return: int_output
        :rtype: int
        """
        converted = self.__convert_by_type(message)
        bit_string = bin(converted)  # konverzija u bit string
        output = bit_string + bit_string[-6:]  # dodaje 6 bitova na kraj stringa (zalihost)
        int_output = int(output, 2)  # konverzija u int
        return int_output

    def __extended_euclidean(self, a, b):
        """
        Proširenim Euklidovim algoritmom dobivamo parametre a i b 
        za koje ap + bq = 1
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
        Za sada se provjerava samo je li string i napravi konverziju. Ako je int vrati poruku kakva jest.
        (Inače bi možda bilo bolje da se bez obzira na poruku kojeg je tipa, pretvori u string i tada izvrši
        manipulacija nad stringom, ali napravljeno je na ovaj način radi lakšeg testiranja samo cijelim brojevima.)
        :param message:
        :type message:
        :return: message
        :rtype: any
        """
        if isinstance(message, str):
            message = Cryptodome.Util.number.bytes_to_long(message.encode('utf-8'))
        else:
            message = message
        return message

    @staticmethod
    def __select_solution(solutions):
        """
        Odabir između 4 moguća rješenja temeljem zalihosti.
        :param solutions: list
        :type solutions:
        :return:
        :rtype:
        """
        for i in solutions:
            binary = bin(i)
            append = binary[-6:]  # uzima zadnjih 6 bitova
            binary = binary[:-6]  # briše 6 bitova

            if append == binary[-6:]:
                return i
        return

    def generate_keys(self):
        """
        Generiranje javnog i privatnog ključa. p i q su privatni ključevi, dok je n javni ključ.
        Javni ključ se dobije množenjem p i q. Privatni ključ je tuple od p i q.
        Nakon generiranja ključeva, isti se čuvaju u objektu radi kasnijeg korištenja.
        """
        p = self.__generate_prime_number()
        q = self.__generate_prime_number()
        if p == q:  # prosti brojevi ne smiju biti isti
            print(p, q, "Numbers cannot be same! Generating again...")
            return self.generate_keys()
        n = p * q
        self.set_public_key(n)
        self.set_private_key((p, q))

    def encrypt(self, message):
        """
        Enkripcija (šifriranje) se vrši po formuli c=m^2 mod n gdje je c cipher tekst.
        :param message:
        :type message: string ili int
        :return: pow(message, 2, self.get_public_key()) --> cipher text
        :rtype: int
        """
        self.__message = message
        message = self.__convert_message(message)
        return pow(message, 2, self.get_public_key())

    def decrypt(self, cipher):
        """
        Dekripcija je rezultat traženja kvadrntih korijena c(mod n)
        Za isto se koristi Kineski teorem o ostacima te proširani Euklidov algoritam
        :param cipher: cipher tekst
        :type cipher: int
        :return: decrypted_text
        :rtype: Any
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
        Ako je poruka prije šifriranja  string, onda se rješenje formatira i iz njega dobije
        dekodirani string (otvoreni tekst). Inače vrati bez promjene.
        :param plain_text: tekst dobiven iz dekripcije
        :type plain_text: Any
        :return: text_decrypted
        :rtype: string ili int
        """
        if isinstance(self.__message, str):
            formatted_text = format(plain_text, 'x')
            text_decrypted = bytes.fromhex(formatted_text).decode()
        else:
            text_decrypted = plain_text
        return text_decrypted


if __name__ == '__main__':
    rabin = Rabin(512)
    rabin.generate_keys()

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