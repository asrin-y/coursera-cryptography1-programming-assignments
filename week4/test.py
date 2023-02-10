from tqdm import tqdm
from time import sleep
import threading

PROGRESS_BAR_CONTINUE = False

def progress_bar(iteration: int):
    global PROGRESS_BAR_CONTINUE
    for i in tqdm (range (iteration), desc="Loading..."):
        while not PROGRESS_BAR_CONTINUE:
            sleep(0.5)
        PROGRESS_BAR_CONTINUE = False

progress_bar_thread = threading.Thread(target=progress_bar, args=(10,)) 
progress_bar_thread.start()

while True:
    input("")
    PROGRESS_BAR_CONTINUE = True
