#!/bin/env python3

from hashlib import md5, sha1, sha256
import threading
from argparse import ArgumentParser


banner = """\
                            __   .__                       .___                 
  ________________    ____ |  | _|  |__   ____ _____     __| _/   ______ ___.__.
_/ ___\_  __ \__  \ _/ ___\|  |/ /  |  \_/ __ \\\__  \   / __ |    \____ <   |  |
\  \___|  | \// __ \\\  \___|    <|   Y  \  ___/ / __ \_/ /_/ |    |  |_> >___  |
 \___  >__|  (____  /\___  >__|_ \___|  /\___  >____  /\____ | /\ |   __// ____|
     \/           \/     \/     \/    \/     \/     \/      \/ \/ |__|   \/   

By Leon Mailfert
"""


class Cracker:
    def __init__(self, args) -> None:
        self.args = args
        self.running = True
        self.hash = args.hash
        self.result = ""
        self.wordlist = self.open_file()
        self.hasher = self.set_hasher()

    def run(self):
        self.crack_hash()
        self.close_file()
        if self.result:
            print(f"[*] Cracked: {self.result}")
        else:
            print("[X] Not found.")

    def crack_hash(self):
        
        def hasher(word):
            if self.hasher(word.strip().encode()).hexdigest() == self.hash:
                self.running = False
                self.result = word
    
        for word in self.wordlist:
            while self.running:
                if threading.active_count() < 50:
                    thread = threading.Thread(target=hasher, args=(word,))
                    thread.start()
                    break
                else:
                    continue
            else:
                break


    def open_file(self):
        return open(self.args.wordlist, "rt")

    def close_file(self):
        self.wordlist.close()
    
    def set_hasher(self):
        return eval(f"{args.hashtype}")

print(banner)
parser = ArgumentParser()
parser.add_argument("hash", help="The hash to be cracked.")
parser.add_argument("wordlist", help="A list containing passwords, one per line")
parser.add_argument("--hashtype", metavar="hashtype", help="The hash type",
                        choices=["md5", "sha1", "sha256"], default="md5")
args = parser.parse_args()

Cracker(args).run()