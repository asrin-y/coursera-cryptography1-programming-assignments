from Crypto.Hash import SHA256
import io

def compute_hash(block: bytes) -> bytes:
    hash_object = SHA256.new(block)
    return hash_object.digest()

# read_file reads the file in 1024 bytes blocks and
# return a list that contains all the file seperated
# into 1024 bytes blocks
def read_file(file: io.BufferedReader) -> list:
    file_blocks = []
    fb = file.read(1024)
    while len(fb) > 0:
        file_blocks.append(fb)
        fb = file.read(1024)
    return file_blocks

# hash_file iterates the file that is seperated by 1024 bytes
# blocks and starts the iteration of all_blocks at the end of the list
# It appends next block's hash (i.e. the hash that was computed at the
# previous iteration) to the block and hashes it. Once it reaches the 
# very first element of the list, it computes the hash of second blocks
# hash appended to first block and returns that value with updated blocks.
def hash_file(file: io.BufferedReader) -> list:
    file_blocks = read_file(file)
    blocks_range = range(len(file_blocks)-1, -1, -1) # last_index, last_index-1, last_index-2. ..... 2, 1, 0

    prev_blocks_hash = bytes(0)
    for i in blocks_range:
        file_blocks[i] += prev_blocks_hash
        prev_blocks_hash = compute_hash(file_blocks[i])

    return prev_blocks_hash.hex(), file_blocks

def main():
    file_location = "./6.1.intro.mp4"
    file = open(file_location, "rb")
    h_0, file_blocks = hash_file(file)
    print(h_0)

if __name__ == '__main__':
    main()
