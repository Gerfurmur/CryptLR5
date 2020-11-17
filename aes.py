from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


block_size = 16
block_counter_size = 4
byte_modulo = 256
PKCS5 = set(i for i in range(1, block_size + 1))
aes_modes = {'ECB', 'CBC', 'CFB', 'OFB', 'CTR'}


def byte_xor(bytearray1, bytearray2):
    """
    xor of two bytearrays with equal length
    """
    return bytes([byte1 ^ byte2 for byte1, byte2 in zip(bytearray1, bytearray2)])


def pad(data, padding):
    """
    :param data: encrypting data - bytes
    :param padding: supplementation in form PKCS5
    :return: supplemented data - bytes
    """
    global block_size
    result = b''
    for i in range(block_size - padding[0]):
        result += data[i].to_bytes(length=1, byteorder='big')
    for i in range(padding[0]):
        result += (data[block_size - padding[0] + i] ^ padding[0]).to_bytes(length=1, byteorder='big')
    return result


def increase_counter_block(counter, iv):
    """
    increase initial vector by counter
    """
    global block_size, block_counter_size, byte_modulo
    result = iv[:block_size - block_counter_size]
    counter = counter.to_bytes(length=block_counter_size, byteorder='big')
    ost = (iv[-1] + counter[-1]) // byte_modulo
    mod = (iv[-1] + counter[-1]) % byte_modulo
    block = mod.to_bytes(length=1, byteorder='little')
    for i in range(1, block_counter_size):
        mod = (iv[-1 - i] + counter[-1 - i] + ost) % byte_modulo
        ost = (iv[-1 - i] + counter[-1 - i] + ost) // byte_modulo
        block += mod.to_bytes(length=1, byteorder='little')
    result += block[::-1]
    return result


def aes_block_encrypt(key, data, is_final_block, padding=b'\x00'):
    """
    Function encrypts one 16 bytes length block using AES encryption with ECB mode
    :param key: a key, that used for encryption - bytes
    :param data: encrypting data - bytes
    :param is_final_block: flag
    :param padding: supplementation in form PKCS5
    :return: encrypted data block - bytes
    """
    pad_data = data
    if is_final_block:
        pad_data = pad(data, padding)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad_data)


def aes_block_decrypt(key, ciphertext):
    """
    Function decrypts one 16 bytes length block using AES decryption with ECB mode
    :param key: a key, that was used for encryption - bytes
    :param ciphertext: encrypted data - bytes
    :return: decrypted data block - bytes
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


def encrypt(key, data, mode='ECB', iv=None):
    """
    Encrypt data with AES encryption and key=key. There are 5 modes:
    ECB, CBC, CFB, OFB, CTR
    :param key: bytes or bytearray
    :param data: bytes, bytearray
    :param mode: str, default=ECB
    :param iv: bytes or bytearray, using for last 4 modes
    :return: bytes
    """
    global block_size
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key: expected bytes or bytearray, but got {}".format(type(key).__name__))
    elif len(key) != 16:
        raise ValueError("key: expected length 16 bytes, but got {}".format(len(key)))
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data: expected bytes or bytearray, but got {}".format(type(data).__name__))
    blocks_number = len(data) // block_size
    blocks = []
    for block_num in range(blocks_number):
        blocks.append(data[block_size * block_num:block_size * (block_num + 1)])
    if blocks_number < len(data) / block_size:
        blocks.append(data[block_size * blocks_number:])
    cipherdata = b''
    last_block = blocks[-1]
    padding = (block_size - len(blocks[-1])).to_bytes(length=1, byteorder='big')
    if mode == 'ECB':
        for block_num in range(len(blocks) - 1):
            cipherdata += aes_block_encrypt(key, blocks[block_num], False)
        last_block = last_block.ljust(block_size, b'\x00')
        cipherdata += aes_block_encrypt(key, last_block, True, padding)
    else:
        if iv is None:
            iv = get_random_bytes(block_size)
        elif not isinstance(iv, (bytes, bytearray)):
            raise TypeError("initial vector: expected bytes or bytearray, but got {}".format(type(iv).__name__))
        elif len(iv) != 16:
            raise ValueError("initial vector: expected length 16 bytes, but got {}".format(len(iv)))
        elif mode == 'CBC':
            cipher_blocks = [aes_block_encrypt(key, byte_xor(blocks[0], iv), False)]
            for block_num in range(1, len(blocks) - 1):
                temp = byte_xor(blocks[block_num], cipher_blocks[-1])
                cipher_blocks.append(aes_block_encrypt(key, temp, False))
            last_block = last_block.ljust(block_size, b'\x00')
            temp = byte_xor(last_block, cipher_blocks[-1])
            cipher_blocks.append(aes_block_encrypt(key, temp, True, padding))
            cipherdata = iv + b''.join(cipher_blocks)
        elif mode == 'CFB':
            cipher_blocks = [byte_xor(blocks[0], aes_block_encrypt(key, iv, False))]
            for block_num in range(1, len(blocks) - 1):
                previous = cipher_blocks[-1]
                cipher_blocks.append(byte_xor(blocks[block_num], aes_block_encrypt(key, previous, False)))
            previous = cipher_blocks[-1]
            cipher_blocks.append(byte_xor(last_block, aes_block_encrypt(key, previous, False)))
            cipherdata = iv + b''.join(cipher_blocks)
        elif mode == 'OFB':
            output = aes_block_encrypt(key, iv, False)
            cipher_blocks = [byte_xor(blocks[0], output)]
            for block_num in range(1, len(blocks) - 1):
                output = aes_block_encrypt(key, output, False)
                cipher_blocks.append(byte_xor(blocks[block_num], output))
            output = aes_block_encrypt(key, output, False)
            cipher_blocks.append(byte_xor(last_block, output))
            cipherdata = iv + b''.join(cipher_blocks)
        elif mode == 'CTR':
            counter = 0
            counter_block = increase_counter_block(counter, iv)
            output = aes_block_encrypt(key, counter_block, False)
            cipher_blocks = [byte_xor(blocks[0], output)]
            for block_num in range(1, len(blocks) - 1):
                counter += 1
                counter_block = increase_counter_block(counter, iv)
                output = aes_block_encrypt(key, counter_block, False)
                cipher_blocks.append(byte_xor(blocks[block_num], output))
            counter += 1
            counter_block = increase_counter_block(counter, iv)
            output = aes_block_encrypt(key, counter_block, False)
            cipher_blocks.append(byte_xor(last_block, output))
            cipherdata = iv + b''.join(cipher_blocks)
        else:
            raise ValueError("mode: expected one of (ECB, CBC, CFB, OFB, CTR), but got {}".format(mode))
    return cipherdata


def decrypt(key, cipherdata, mode='ECB'):
    """
    Decrypt data with AES decryption and key=key. There are 5 modes:
    ECB, CBC, CFB, OFB, CTR
    :param key: bytes or bytearray
    :param cipherdata: bytes, bytearray
    :param mode: str, default=ECB
    :param iv: first 16 bytes in cipherdata - bytes or bytearray, using for last 4 modes
    :return: bytes
    """
    global block_size
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key: expected bytes or bytearray, but got {}".format(type(key).__name__))
    if not isinstance(cipherdata, (bytes, bytearray)):
        raise TypeError(
            "cipherdata: expected bytes or bytearray, but got {}".format(type(cipherdata).__name__))
    blocks_number = len(cipherdata) // block_size
    blocks = []
    for block_num in range(blocks_number):
        blocks.append(cipherdata[block_size * block_num:block_size * (block_num + 1)])
    if blocks_number < len(cipherdata) / block_size:
        blocks.append(cipherdata[block_size * blocks_number:])
    decryptdata = b''
    if mode == 'ECB':
        for block_num in range(len(blocks) - 1):
            decryptdata += aes_block_decrypt(key, blocks[block_num])
        last_block = blocks[-1]
        decryptlast_block = aes_block_decrypt(key, last_block)
        padding = decryptlast_block[-1]
        if padding in PKCS5:
            decryptlast_block = decryptlast_block[:block_size - padding]
        decryptdata += decryptlast_block
    elif mode == 'CBC':
        decrypted_blocks = []
        for block_num in range(1, len(blocks)):
            decrypted_blocks.append(byte_xor(blocks[block_num - 1], aes_block_decrypt(key, blocks[block_num])))
        padding = decrypted_blocks[-1][-1]
        if padding in PKCS5:
            decrypted_blocks[-1] = decrypted_blocks[-1][:block_size - padding]
        decryptdata = b''.join(decrypted_blocks)
    elif mode == 'CFB':
        decrypted_blocks = []
        for block_num in range(1, len(blocks)):
            temp = aes_block_encrypt(key, blocks[block_num - 1], False)
            decrypted_blocks.append(byte_xor(blocks[block_num], temp))
        decryptdata = b''.join(decrypted_blocks)
    elif mode == 'OFB':
        output = aes_block_encrypt(key, blocks[0], False)
        decrypted_blocks = [byte_xor(blocks[1], output)]
        for block_num in range(2, len(blocks)):
            output = aes_block_encrypt(key, output, False)
            decrypted_blocks.append(byte_xor(blocks[block_num], output))
        decryptdata = b''.join(decrypted_blocks)
    elif mode == 'CTR':
        counter = 0
        counter_block = increase_counter_block(counter, blocks[0])
        output = aes_block_encrypt(key, counter_block, False)
        decrypted_blocks = [byte_xor(blocks[1], output)]
        for block_num in range(2, len(blocks)):
            counter += 1
            counter_block = increase_counter_block(counter, blocks[0])
            output = aes_block_encrypt(key, counter_block, False)
            decrypted_blocks.append(byte_xor(blocks[block_num], output))
        decryptdata = b''.join(decrypted_blocks)
    else:
        raise ValueError("mode: expected one of (ECB, CBC, CFB, OFB, CTR), but got {}".format(mode))
    return decryptdata

