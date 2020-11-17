import aes
import HMAC


class Mode:
    ecnryption = "encryption"
    decryption = "decryption"


class auth_encryptor:
    """
    Класс, реализующий аутентифицированное
    шифрование в режиме Encrypt-Then-Mac
    """
    block_size = 16

    def __init__(self, mode, aes_key=None, mac_key=None):
        """
        Конструктор, который определяет режим работы
        mode = "encrypt" шифрует и вычисляет код аутентичности
        mode = "decrypt" расшифровывает и выполняет проверку кода аутентичности
        :param mode: Mode
        """
        if not isinstance(mode, str):
            raise TypeError("mode: expected string, but got {}".format(type(mode).__name__))
        mode = mode.lower()
        if mode != Mode.ecnryption and mode != Mode.decryption:
            raise ValueError("mode: expected 'encryption' or 'decryption', but got {}".format(mode))
        self.mode = mode
        self.aes_key = None
        self.mac_key = None
        self.mac = HMAC.HMAC()
        self.aes_mode = "CTR"
        self.initial_vector = None
        self.data = b""
        self.encrypted_data = None
        if aes_key is not None and mac_key is not None:
            self.set_key(aes_key, mac_key)

    def set_key(self, aes_key, mac_key):
        """
        Инициализирует объект шифрования ключом aes_key
        и mac_key для вычисления/проверки кода аутентичности
        :param aes_key: bytes/bytearray
        :param mac_key: bytes/bytearray
        """
        if not isinstance(aes_key, (bytes, bytearray)):
            raise TypeError("aes_key: expected bytes or bytearray, but got {}".format(type(aes_key).__name__))
        if not isinstance(mac_key, (bytes, bytearray)):
            raise TypeError("mac_key: expected bytes or bytearray, but got {}".format(type(mac_key).__name__))
        if len(aes_key) != auth_encryptor.block_size:
            raise ValueError("aes_key: expected length = 16, but got {}".format(len(aes_key)))
        if len(mac_key) != auth_encryptor.block_size:
            raise ValueError("mac_key: expected length = 16, but got {}".format(len(mac_key)))
        if aes_key == mac_key:
            raise ValueError("aes_key, mac_key: expected different keys")
        self.aes_key = aes_key
        self.mac_key = mac_key
        self.mac.set_key(mac_key)

    def add_block(self, data, is_final=False):
        """
        Добавляет блок данных для аутентифицированного зашифрования
        или расшифрования. В случае передачи флага is_final должен
        вычисляться\проверяться код аутентичности (в зависимости от режима mode).
        При расшифровании, в случае неуспешной проверки кода аутентичности
        должна выводиться ошибка.
        :param data_block: bytes/bytearray
        :param is_final_block: boolean
        :return:
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data: expected bytes or bytearray, but got {}".format(type(data).__name__))
        self.data += data
        if is_final:
            if self.mode == Mode.ecnryption:
                self.encrypted_data = aes.encrypt(self.aes_key, self.data, self.aes_mode, self.initial_vector)
                return self.mac.compute_mac(self.encrypted_data)
            else:
                if not self.mac.verify_mac(self.data[:-self.mac.result_size], self.data[-self.mac.result_size:]):
                    raise ValueError("Attention: transmitted data were changed")
                return True

    def process_data(self, data, iv=None):
        if self.mode == Mode.ecnryption:
            if not isinstance(iv, (bytes, bytearray)):
                raise TypeError("initial_vector: expected bytes or bytearray, but got {}".format(type(iv).__name__))
            self.initial_vector = iv
            result_mac = self.add_block(data, True)
            self.data = b""
            return self.encrypted_data + result_mac
        self.add_block(data, True)
        return aes.decrypt(self.aes_key, self.data[:-self.mac.result_size], self.aes_mode)


