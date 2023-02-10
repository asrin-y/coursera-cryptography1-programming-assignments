import requests
from tqdm import tqdm #pip install tqdm
from time import sleep
import threading

URL = "http://crypto-class.appspot.com/po?er="
PROGRESS_BAR_CONTINUE = 0

# f20bdba6ff29eed7b046d1df9fb70000 -> IV
# 58b1ffb4210a580f748b4ac714c001bd
# 4a61044426fb515dad3f21f18aa577c0
# bdf302936266926ff37dbf7035d5eeb4

# get error code of the request
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

def format_iv(iv: str, intermediate_state: str, byte_number: int) ->str:
    for i in range(1, byte_number):
        replace_hex = xor(int(intermediate_state[32-2*i:34-2*i],16),byte_number,0)
        iv = iv[:32-2*i] + replace_hex + iv[34-2*i:]
    return iv

def progress_bar(iteration: int):
    global PROGRESS_BAR_CONTINUE
    for i in tqdm (range (iteration), desc="Decrypting..."):
        while PROGRESS_BAR_CONTINUE == 0:
            sleep(0.1)
        PROGRESS_BAR_CONTINUE-=1
        sleep(0.1)


ciphertext_blocks = parse("f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4",32)

progress_bar_thread = threading.Thread(target=progress_bar, args=((len(ciphertext_blocks)-1)*16*256,)) 
progress_bar_thread.start()
plaintext = ""

for t in range(1,len(ciphertext_blocks)):
    intermediate_state = "0" * 32
    iv = ciphertext_blocks[t-1]

    found = False
    for g in range(0,256):
        PROGRESS_BAR_CONTINUE+=1
        iv = iv[:30] + double_digit_hex(g)
        ciphertext = iv + ciphertext_blocks[t]
        err_code = get_request_error_code(ciphertext)
        #print(1,double_digit_hex(g),err_code, end="\r")
        if(err_code != 403):
            if(double_digit_hex(g) != ciphertext_blocks[t-1][30:32]):
                found = True
                break
    PROGRESS_BAR_CONTINUE += 255-g
    if not found:
        g = int(ciphertext_blocks[t-1][30:32],16)
    #print(1,double_digit_hex(g),err_code)
    
    intermediate_state = intermediate_state[:30] + xor(g, 1, 0)

    for i in range(2,17):
        iv = format_iv(iv, intermediate_state, i)

        for g in range(0,256):
            PROGRESS_BAR_CONTINUE+=1
            iv = iv[:32-2*i] + double_digit_hex(g) + iv[34-2*i:]
            ciphertext = iv + ciphertext_blocks[t]
            err_code = get_request_error_code(ciphertext)
            #print(i,double_digit_hex(g),err_code, end="\r")
            if(err_code != 403):
                #print(i,double_digit_hex(g),err_code)
                break
        PROGRESS_BAR_CONTINUE += 255-g
        intermediate_state = intermediate_state[:32-2*i] + xor(g, i, 0) + intermediate_state[34-2*i:]

    xor_a_b = ""
    for i in range(0,16):
        char_a = intermediate_state[i*2:i*2+2]
        char_b = ciphertext_blocks[t-1][i*2:i*2+2]
        char_xor = int(char_a,16) ^ int(char_b,16)
        xor_a_b += chr(char_xor)
    plaintext += xor_a_b

while PROGRESS_BAR_CONTINUE != 0:
    sleep(0.5)
print("Complete")
print(plaintext)