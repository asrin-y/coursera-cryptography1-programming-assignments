# Reading ciphertexts from a file
ciphertexts_file = open("ciphertexts.txt", "r")
ciphertexts = ciphertexts_file.readlines()
ciphertexts_file.close()


# Removing end line characters
for i in range(0,len(ciphertexts)):
    ciphertexts[i] = ciphertexts[i].strip() 


# Initializing the key with all zeros (the key string here is used as hex values, for example
# the 4th character of key is chr( int( key[8:10] , 16) ))
key = "0" * 1024


# If a space character, 0x20, xor's with an uppercase letter, the result becomes the lowercase letter and vice versa.
# If a space character (" ") is xor'd with a space result becomes 0x00
# This array contains all uppercase and lowercase letters and null character (0x00)
# So this code is going to check all combinations of a ciphertext xor'd with other ciphertexts that encrypted using same stream cipher key
# If at one index, one message includes a space and other includes a space or a letter, it will be in this array.
all_letters =   [0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 
                0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 
                0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 
                0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 
                0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 
                0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a]


def replace_string(string: str, index: int, char: str):
    return string[0:index] + char + string[index+1:len(string)]


def hex_xor(a, b): # xor 2 strings that contains hex values with different lengths
    if(type(a) == int):
        a = ciphertexts[a]
    b = ciphertexts[b]
    if len(a) > len(b):
       return "".join([str(hex(int(x,16) ^ int(y,16)))[2:] for (x, y) in zip(a[:len(b)], b)])
    else:
       return "".join([str(hex(int(x,16) ^ int(y,16)))[2:] for (x, y) in zip(a, b[:len(a)])])
    

# This function xor's all ciphertext with all other ciphertexts and increments the counter
# of that index. At the end of the loop. Values of indeces is checked whether it is "length(ciphertexts) - 1".
# The value of "length(ciphertexts) - 1" means it has a very high probability that that index 
# includes space because the result becomes one of the all_letters array in each xor with other ciphertexts.
# This "length(ciphertexts) - 1" value can be seen as a confidence level and it can be decreased according to 
# the number of ciphertexts that someone has. In this case, since there is 11 ciphertexs encrypted with same key,
# plaintexts were obvious even after such a high confidence level.
def find_possible_spaces(a: int): 
    all_possible_space_indeces = []
    spaces_dictionary = {}
    for b in range(0,len(ciphertexts)):
        if(a == b):
            continue
        xor_a_b = hex_xor(a,b)
        for i in range(0,len(xor_a_b)//2):
            char = xor_a_b[(i*2) : (i*2)+2]
            char = int(char,16)
            if(char in all_letters):
                if(spaces_dictionary.__contains__(i)):
                    spaces_dictionary[i]+=1
                else:
                    spaces_dictionary[i] = 1

    for i in spaces_dictionary:
        if(spaces_dictionary[i] == (len(ciphertexts)-1)):
            all_possible_space_indeces.append(i)
    all_possible_space_indeces.sort()
    return all_possible_space_indeces


# This function updates the key according to the possible spaces found at above function.
# As stated at the beginning, the key string here is used as hex values, for example
# the 4th character of key is chr( int( key[8:10] , 16) )
def update_key():
    global key
    for a in range(0,len(ciphertexts)):
        spaces_of_ciphertext_a = find_possible_spaces(a)
        ciphertext_a = ciphertexts[a]
        for i in spaces_of_ciphertext_a:
            if(i*2 >= len(ciphertext_a)):
                continue
            part_of_the_key = str(hex(int(ciphertext_a[i*2],16) ^ 0x2))[2] + str(hex(int(ciphertext_a[i*2+1],16) ^ 0x0))[2]
            if(key[i*2:i*2+2] == "00"):
                key = replace_string(key,i*2,part_of_the_key[0])
                key = replace_string(key,i*2+1,part_of_the_key[1])


# This function prints plaintexts by xoring ciphertexs with the key
# If that part of the key is still unknow, it prints "?" to that location
# To specify the index of the character in manual_update_function, indeces
# of characters in strings are stated below them.
def print_plaintexts():
    for i in range(0,len(ciphertexts)):
        print()
        xor_w_key = hex_xor(key,i)
        print(f"{i} ->  \t|",end="")
        length = len(ciphertexts[i])//2
        for i in range(0,length):
            if(key[i*2:i*2+2] == "00"):
                print("?",end="")
                continue
            char_of_plaintexts = chr(int(xor_w_key[i*2:i*2+2],16))
            print(char_of_plaintexts,end="")
        print()
        print(f"         ",end="")
        for i in range(0,length):
            print(i%10,end="")
    print()


# After the auto filling of the key according to spaces, there are still many unknowns in the key.
# This function updates the key according to the correct string that should exist in a specific location of
# one of the plaintexts. For example if there is a "cipher?exts" in ciphertext4 at the 26th location, 
# manual_update_key(4, 26, "t") would set the key accordingly.
def manual_update_key(ciphertext_no, index_start, replace_string):
    global key
    length = len(replace_string)
    index_end = index_start + length
    part_of_ciphertext = ciphertexts[ciphertext_no][index_start*2:index_end*2]
    for i in range(0,length):
        string_char = str(hex(ord(replace_string[i])))[2:]
        part_of_ciphertext_parse = part_of_ciphertext[i*2:i*2+2]
        key_replace_char = str(hex(int(string_char[0],16) ^ int(part_of_ciphertext_parse[0],16)))[2]\
                            + str(hex(int(string_char[1],16) ^ int(part_of_ciphertext_parse[1],16)))[2]
        key = key[0:index_start*2] + key_replace_char + key[index_start*2+2:]


def main():
    update_key()

    manual_update_key(10,2,"e")
    manual_update_key(10,7,"r")
    manual_update_key(0,10,"t")
    manual_update_key(0,14,"t")
    manual_update_key(0,21,"b")
    manual_update_key(5,25,"y")
    manual_update_key(5,26,"p")
    manual_update_key(5,30,"r")
    manual_update_key(10,31,"n")
    manual_update_key(10,32,"g")
    manual_update_key(7,54,"o")
    manual_update_key(9,49,"p")
    manual_update_key(9,50,"t")
    manual_update_key(0,41,"c")
    manual_update_key(0,42,"o")
    manual_update_key(1,40,"t")
    manual_update_key(3,39,"p")
    manual_update_key(0,33,"q")
    manual_update_key(0,34,"u")
    manual_update_key(0,35,"a")
    manual_update_key(0,36,"n")
    manual_update_key(6,81,"o")
    manual_update_key(6,82,"r")
    manual_update_key(6,83,"c")
    manual_update_key(6,84,"e")

    print_plaintexts()

if(__name__ == "__main__"):
    main()