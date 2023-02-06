from os import urandom

from Crypto.Cipher import AES


def AES_ECB_encrypt(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def AES_ECB_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# This function adds padding according to the PKCS5 padding scheme if required.
def add_padding(object: bytes) -> bytes:
    padding_needed = 16 - len(object)
    if padding_needed == 0:
        return object
    for i in range(0, padding_needed):
        object = object + int.to_bytes(padding_needed, 1, "big")
    return object


def remove_padding(object: bytes) -> bytes:
    padding_length = object[15]
    message_length = 16 - padding_length
    object = object[:message_length]
    return object

# This function parses string to desired sizes and returns the list of them.
def parse_string(s, size: int) -> list:
    length = len(s)
    sub_strings = [s[i:i + size] for i in range(0, length, size)]
    return sub_strings

# to xor bytes objects
def bytes_xor(b1: bytes, b2: bytes) -> bytes:
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)


# This function formats the given string to according block 
# sizes in bytes object, in this case 16 bytes.
def format_encrypt_blocks_cbc(string: str) -> list:
    parsed_text = parse_string(string, 16)
    for i in range(0, len(parsed_text)):
        parsed_text[i] = add_padding(bytes(parsed_text[i], "ascii"))
    return parsed_text


# This function formats the given bytes object to appropriate block size
def format_decrypt_blocks(byte_object: bytes) -> list:
    parsed_text = parse_string(byte_object, 16)
    return parsed_text


# Message is an ascii encoded string, key is a hex string.
# If no iv is provided, os.urandom is used.
def AES_CBC_encrypt(message :str, key: str, iv: bytes=urandom(16)) -> str:
    
    key = bytes.fromhex(key)

    plaintext_blocks = format_encrypt_blocks_cbc(message)

    previous_block_ciphertext = iv

    ciphertext = iv
    count = 0
    for block in plaintext_blocks:
        count += 1
        function_input = bytes_xor(previous_block_ciphertext, block)
        function_output = AES_ECB_encrypt(function_input, key)
        ciphertext += function_output
        previous_block_ciphertext = function_output

    return ciphertext.hex()


# Both ciphertext and key are hex strings, bytes object is returned.
def AES_CBC_decrypt(ciphertext :str, key: str) -> bytes:

    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(key)

    iv = ciphertext[0:16]
    ciphertext_blocks = format_decrypt_blocks(ciphertext[16:])

    previous_block_ciphertext = iv

    plaintext = bytes(0)
    count = 0
    for block in ciphertext_blocks:
        count += 1
        function_output = AES_ECB_decrypt(block, key)
        block_plaintext = bytes_xor(previous_block_ciphertext, function_output)
        if count == len(ciphertext_blocks):
            block_plaintext = remove_padding(block_plaintext)
        plaintext = plaintext + block_plaintext
        previous_block_ciphertext = block

    return plaintext

# Function to increment a byte object to use in ctr mode
def increment_bytes(a: bytes) -> bytes:
    incr = int(a.hex(), 16) + 1
    return int.to_bytes(incr, 16, "big")


def format_encrypt_blocks_ctr(string: str) -> list:
    parsed_text = parse_string(string, 16)
    for i in range(0, len(parsed_text)):
        parsed_text[i] = bytes(parsed_text[i], "ascii")
    return parsed_text


# Message is ascii encoded string, key is hex string. If no iv is
# provided os.urandom is used. Returned value is a hex string.
def AES_CTR_encrypt(message: str, key: str, iv: bytes=urandom(16)) -> str:
    
    key = bytes.fromhex(key)
    plaintext_blocks = format_encrypt_blocks_ctr(message)

    ciphertext = iv
    count = 0
    for block in plaintext_blocks:
        count += 1
        function_output = AES_ECB_encrypt(iv, key)
        if count == len(plaintext_blocks):
            function_output = function_output[:len(block)]
        ciphertext_block = bytes_xor(function_output, block)
        ciphertext += ciphertext_block
        iv = increment_bytes(iv)

    return ciphertext.hex()


# Both ciphertext and key are hex strings, bytes object is returned.
def AES_CTR_decrypt(ciphertext: str, key: str) -> bytes:

    key = bytes.fromhex(key)
    ciphertext = bytes.fromhex(ciphertext)

    iv = ciphertext[0:16]
    ciphertext_blocks = format_decrypt_blocks(ciphertext[16:])

    plaintext = bytes(0)
    count = 0
    for block in ciphertext_blocks:
        count += 1
        function_output = AES_ECB_encrypt(iv, key)
        if count == len(ciphertext_blocks):
            function_output = function_output[:len(block)]
        plaintext_block = bytes_xor(function_output, block)
        plaintext = plaintext + plaintext_block
        iv = increment_bytes(iv)

    return plaintext


def main():

    key = "140b41b22a29beb4061bda66b6747e14"
    ciphertext = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"

    plaintext = AES_CBC_decrypt(ciphertext,key)

    print(plaintext.decode())

if __name__ == '__main__':
    main()
