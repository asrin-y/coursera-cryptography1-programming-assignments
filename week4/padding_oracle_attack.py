import requests
from tqdm import tqdm # pip install tqdm
from time import sleep
import threading


# get error code of the request
URL = "http://crypto-class.appspot.com/po?er="
def get_request_error_code(ciphertext: str) -> int:
    return requests.get(url= URL + ciphertext).status_code


# parse given string to desired size
def parse(s: str, size: int) -> list:
    length = len(s)
    parsed = [s[i:i + size] for i in range(0, length, size)]
    return parsed


# xor 3 integers and return the result in hex
def xor(a: int, b: int, c: int) -> str:
    xor_result = a ^ b ^ c
    return double_digit_hex(xor_result)


# format int to double digit hex
def double_digit_hex(number: int) -> str:
    value = hex(number)[2:]
    if len(value) == 1:
        value = "0" + value
    return value


# Format iv according to desired byte that is trying to be decrypted
# assume byte_number is 4, returned iv will be in the format 
# "????....xx040404" such that xx is the target byte
def format_iv(iv: str, intermediate_state: str, byte_number: int) -> str:
    for i in range(1, byte_number):
        replace_hex = xor(int(intermediate_state[32-2*i:34-2*i],16),byte_number,0)
        iv = iv[:32-2*i] + replace_hex + iv[34-2*i:]
    return iv


# Progress bar to track decryption
# PROGRESS_BAR is a global variable that tracks the
# progress of the operation. Each iteration in decryption
# increments PROGRESS_BAR and each loop in progress_bar_thread
# is decrements while reflecting the progress to the terminal
PROGRESS_BAR = 0
def progress_bar_thread(iteration: int) -> None:
    global PROGRESS_BAR
    for i in tqdm (range (iteration), desc="Decrypting..."):
        while PROGRESS_BAR == 0:
            sleep(0.05)
        PROGRESS_BAR-=1
        sleep(0.05)
    print("Complete")


# Since decryption of CBC is parallelizable, decryption is done via threads.
# Each thread decrypts one plaintext block.
def decrypt_thread(ciphertext_blocks: list, plaintexts: dict, block_no: int) -> None:
    global PROGRESS_BAR

    # intermediate_state means the output of the AES-ECB decryption function,
    # intermediate_state[n] xor ciphertext[n-1] = plaintext[n]
    intermediate_state = "0" * 32 

    iv = ciphertext_blocks[block_no-1]

    found = False
    for g in range(0,256):
        PROGRESS_BAR+=1
        iv = iv[:30] + double_digit_hex(g)
        ciphertext = iv + ciphertext_blocks[block_no]
        err_code = get_request_error_code(ciphertext)
        if(err_code != 403):
            # This comparion exists only at the decryption of last byte of
            # block (i.e. first byte to be found). Since the block can be
            # already padded or by some chance last two bytes of
            # the block may be "???...?0202", the loop cannot terminate
            # at the first correct padding. If a correct padding is found
            # but the g value is same as the part of the original ciphertext
            # loop has to continue iteration because some other padding may
            # be the case. If no other valid padding is found, it means that
            # block is already padded 1 byte.
            if(double_digit_hex(g) != ciphertext_blocks[block_no-1][30:32]):
                found = True
                break

    # Since iteration is broken when the correct value is found,
    # remaining iterations are marked done by incrementing the
    # PROGRESS_BAR value by remaining iterations
    PROGRESS_BAR += 255-g

    if not found:
        g = int(ciphertext_blocks[block_no-1][30:32],16)
    
    intermediate_state = intermediate_state[:30] + xor(g, 1, 0)

    for i in range(2,17):
        iv = format_iv(iv, intermediate_state, i)

        for g in range(0,256):
            PROGRESS_BAR+=1
            iv = iv[:32-2*i] + double_digit_hex(g) + iv[34-2*i:]
            ciphertext = iv + ciphertext_blocks[block_no]
            err_code = get_request_error_code(ciphertext)
            if(err_code != 403):
                break
        PROGRESS_BAR += 255-g
        intermediate_state = intermediate_state[:32-2*i] + xor(g, i, 0) + intermediate_state[34-2*i:]

    xor_a_b = ""
    for i in range(0,16):
        char_a = intermediate_state[i*2:i*2+2]
        char_b = ciphertext_blocks[block_no-1][i*2:i*2+2]
        char_xor = int(char_a,16) ^ int(char_b,16)
        xor_a_b += chr(char_xor)
    plaintexts[block_no] = xor_a_b


def decrypt(ciphertext: str) -> str:

    ciphertext_blocks = parse(ciphertext, 32)

    progress_bar = threading.Thread(target=progress_bar_thread, args=((len(ciphertext_blocks)-1)*16*256,)) 
    progress_bar.start()

    decrypt_threads = []
    plaintexts = {}
    for i in range(1,len(ciphertext_blocks)):
        decryptThread = threading.Thread(target=decrypt_thread, args=(ciphertext_blocks, plaintexts, i)) 
        decryptThread.start()
        decrypt_threads.append(decryptThread)
    
    for decryptThread in decrypt_threads:
        decryptThread.join()

    plaintext = ""
    for i in range(1,len(ciphertext_blocks)):
        plaintext += plaintexts[i]

    progress_bar.join()

    print(plaintext)

    return plaintext


def main():
    ciphertext = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4"
    decrypt(ciphertext)


if __name__ == "__main__":
    main()