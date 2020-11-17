from hashlib import sha256


def byte_xor(bytearray1, bytearray2):
    """
    Производит поэлементное сложение по модулю 2
    bytearray1: первый массив байт
    bytearray2: второй массив байт
    """
    return bytes([a ^ b for a, b in zip(bytearray1, bytearray2)])


class HMAC:
    blocksize = 64
    result_size = 32
    xor_5C = bytes(0x5C for x in range(64))
    xor_36 = bytes(0x36 for x in range(64))

    def __init__(self, key=None):
        """
        Создание нового объекта HMAC, который использует SHA256.
        key: массив байт, ключ.
        msg: массив байт, данные.
        """
        self.key = key
        if callable(sha256):
            self.digest_cons = sha256
        self.opad = None
        self.ipad = None
        if key is not None:
            self.set_key(key)

    def set_key(self, key):
        """
        Инициализирует объект HMAC ключом key
        :param key: bytes
        """
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key: expected bytes or bytearray, but got {}".format(type(key).__name__))
        if len(key) > HMAC.blocksize:
            key = self.digest_cons(key).digest()
        key = key.ljust(HMAC.blocksize, b'\0')
        self.key = key
        self.opad = byte_xor(key, self.xor_5C)
        self.ipad = byte_xor(key, self.xor_36)

    def mac_add_block(self, data):
        """Наполнение данными из msg в наш хешируемый объект."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data: expected bytes or bytearray, but got {}".format(type(data).__name__))
        self.ipad += data

    def mac_finalize(self):
        """
        Возврат значения хеша
        :return: bytes
        """
        h = self.opad
        h += (self.digest_cons(self.ipad).digest())
        auth = self.digest_cons(h).digest()
        self.opad = byte_xor(self.key, self.xor_5C)
        self.ipad = byte_xor(self.key, self.xor_36)
        return auth

    def compute_mac(self, data):
        """
        Вычисляет код аутентичности для прозвольных
        данных, используя метод mac_add_block
        data - данные в байтах
        :param data: bytes
        :return: bytes
        """
        self.mac_add_block(data)
        return self.mac_finalize()

    def verify_mac(self, data, tag):
        """
        Проверяет код аутентичности для прозвольных данных,
        используя метод compute_mac
        :param data: bytes
        :param tag: bytes
        :return: boolean
        """
        if not isinstance(tag, (bytes, bytearray)):
            raise TypeError("tag: expected bytes or bytearray, but got {}".format(type(tag).__name__))
        if self.compute_mac(data) == tag:
            return True
        return False

