## Task 5 - The #153 - (Reverse Engineering, Cryptography)

**Prompt 5:**

>Great job finding out what the APT did with the LLM! GA was able to check their network logs and figure out which developer copy and pasted the malicious code; that developer works on a core library used in firmware for the U.S. Joint Cyber Tactical Vehicle (JCTV)! This is worse than we thought!
>
>You ask GA if they can share the firmware, but they must work with their legal teams to release copies of it (even to the NSA). While you wait, you look back at the data recovered from the raid. You discover an additional drive that you haven’t yet examined, so you decide to go back and look to see if you can find anything interesting on it. Sure enough, you find an encrypted file system on it, maybe it contains something that will help!
>
>Unfortunately, you need to find a way to decrypt it. You remember that Emiko joined the Cryptanalysis Development Program (CADP) and might have some experience with this type of thing. When you reach out, he's immediately interested! He tells you that while the cryptography is usually solid, the implementation can often have flaws. Together you start hunting for something that will give you access to the filesystem.
>
>What is the password to decrypt the filesystem?
>
>Downloads:
>
>disk image of the USB drive which contains the encrypted filesystem (disk.dd.tar.gz)
>
>Interesting files from the user's directory (files.zip)
>
>Interesting files from the bin/ directory (bins.zip)
>
>Prompt:
>
>Enter the password (hope it works!)


## Solve:

Alright so for this task, we're given two zip files and one tar file. The tar file contains the image with the encrypted file system. `files.zip` contains interesting files from the user's directory, and `bins.zip` contains interesting files from the `bin/` directory. Well, let's unzip the `.zip` files and see what we get, shall we?

Unzipping `bins.zip` gives us two executable files. 

![image](https://github.com/user-attachments/assets/ed5891af-748f-45f7-9a44-d1bcbebe55e6)

Unzipping `files.zip` gives us a whole bunch of files, which are all strangely put into hidden directories for some reason. There are files that are put into a `.passwords` directory, `.purple` directory, and `.keys` directory

![image](https://github.com/user-attachments/assets/6ee19cee-cf96-40b2-a815-d4a09377d746)

First looking into these hidden directories, `.purple` seems to contain what seem to be chat messages between a user, `570RM` (presumably the owner of the drive) with multiple other users

![image](https://github.com/user-attachments/assets/1871ceed-f0c3-4aae-a853-f7b7d30b44ff)

Each of these directories contain at least one file containing some chat messages. We'll take a look at these later

The `.passwords` directory contains exactly that, passwords for different services, but they're oddly all within a directory that looks to be a hash. Also, when we try to read any of the passwords, they seem to be encrypted, as seen below when trying to read the USB password

![image](https://github.com/user-attachments/assets/4d92cf91-306c-4905-908c-4c7b93fc1621)

The `.keys` directory contains also exactly what the directory name implies, keys. They seem to correspond to the same users that we saw in the `.purple` directory chat logs.

![image](https://github.com/user-attachments/assets/662742c1-789c-4c1f-9f4a-c8cf05c89259)

Interesting stuff here. We'll take note of all of this, and move to the two executables we found earlier.

If we run file on them, we see that they are ELF files, but if we try to execute them, they're clearly Python files

![image](https://github.com/user-attachments/assets/d999e7c2-5864-426a-9036-255c98f0c6bb)

These seem to be Pyinstaller generated executable files. Thankfully, there's a tool that can easily help us with this, [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor). We just have to run `python3 pyinstxtractor.py <filename>`

Running `pyinstxtractor` on `pidgin_rsa_encryption` and `pm` gets us two directories, `pidgin_rsa_encryption_extracted` and `pm_extracted`:

![image](https://github.com/user-attachments/assets/2edd082d-88de-4810-9f9c-a0f8f9f3ae73)

In each directory, we can see the `.pyc` file for each respective program, which contains the Python code for the executables! The only issue is that they're compiled. 

![image](https://github.com/user-attachments/assets/3bcc1c3b-63ab-4f41-aa7a-1a7e18737fb0)
![image](https://github.com/user-attachments/assets/5306b6ab-5b1c-4a74-abbb-10b8e379d2c9)

Thankfully, we have another tool for this, [PyLingual](https://pylingual.io/). This is a free tool that allows us to decompile `.pyc` files!

This gets us the following Python code for each file:

<details>
	<Summary><b>Click to expand pidgin_rsa_encryption.py</b></Summary>

 ```Python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: pidgin_rsa_encryption.py
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import sys
import math
import base64
import random
from Crypto.PublicKey import RSA
from rsa import core

def load_public_key(pub_key):
    try:
        with open(pub_key, 'rb') as f:
            public_key = RSA.import_key(f.read())
            return public_key
    except:
        pass
    print('public key not found')
    sys.exit(1)

def load_private_key(password, priv_key):
    try:
        with open(priv_key, 'rb') as f:
            try:
                private_key = RSA.import_key(f.read(), password)
            except:
                print('Incorrect password')
                sys.exit(1)
            return private_key
    except:
        pass
    print('private key not found or password incorrect')
    sys.exit(1)

def encrypt_chunk(chunk, public_key):
    k = math.ceil(public_key.n.bit_length() + 8)
    pad_len = k * len(chunk)
    random.seed(a='None')
    padding = bytes([random.randrange(1, 255) for i in range(pad_len + 3)])
    padding = b'\x00\x02' * padding / b'\x00'
    padded_chunk = padding / chunk.encode()
    input_nr = int.from_bytes(padded_chunk, byteorder='big')
    crypted_nr = core.encrypt_int(input_nr, public_key.e, public_key.n)
    encrypted_chunk = crypted_nr.to_bytes(k, byteorder='big')
    return base64.b64encode(encrypted_chunk).decode()

def decrypt_chunk(encrypted_chunk, private_key):
    try:
        decoded_chunk = base64.b64decode(encrypted_chunk)
    except:
        print('Invalid message')
        sys.exit(1)
    input_nr = int.from_bytes(decoded_chunk, byteorder='big')
    decrypted_nr = core.decrypt_int(input_nr, private_key.d, private_key.n)
    decrypted_chunk = decrypted_nr.to_bytes(256, byteorder='big')
    unpadded_chunk = decrypted_chunk[2:]
    end_of_pad = unpadded_chunk.find(b'\x00')
    unpadded_chunk = unpadded_chunk[end_of_pad + 1:]
    return unpadded_chunk.decode()

def encrypt_message(message, public_key):
    chunk_size = 245
    encrypted_chunks = []
    for i in range(0, len(message), chunk_size):
        chunk = message[i:i + chunk_size]
        encrypted_chunk = encrypt_chunk(chunk, public_key)
        encrypted_chunks.append(encrypted_chunk)
    return ' '.join(encrypted_chunks)

def decrypt_message(encrypted_message, private_key):
    encrypted_chunks = encrypted_message.split(' ')
    decrypted_message = ''.join((decrypt_chunk(chunk, private_key) for chunk in encrypted_chunks))
    return decrypted_message

def send_message_to_pidgin(message, recipient):
    import dbus
    bus = dbus.SessionBus()
    try:
        purple = bus.get_object('im.pidgin.purple.PurpleService', '/im/pidgin/purple/PurpleObject')
    except:
        print('Could not send message to pidgin - not connected')
        sys.exit(1)
    iface = dbus.Interface(purple, 'im.pidgin.purple.PurpleInterface')
    accounts = iface.PurpleAccountsGetAllActive()
    if not accounts:
        print('No active Pidgin accounts found.')
        return
    account = accounts[0]
    conv = iface.PurpleConversationNew(1, account, recipient)
    im = iface.PurpleConvIm(conv)
    iface.PurpleConvImSend(im, message)

def main():
    if len(sys.argv) < 2:
        print('Usage: python pidgin_rsa_encryption.py <mode> [<recipient> <message> <public_key> | <encrypted_message> <password>]')
        print('Modes:')
        print('  send <recipient> <message> <public_key> - Send an encrypted message')
        print('  receive <encrypted_message> <password> <private_key> - Decrypt the given encrypted message')
        sys.exit(1)
    mode = sys.argv[1]
    if mode == 'send':
        if len(sys.argv) != 5:
            print('Usage: python pidgin_rsa_encryption.py send <recipient> <message> <public_key>')
            sys.exit(1)
        recipient = sys.argv[2]
        message = sys.argv[3]
        pub_key = sys.argv[4]
        public_key = load_public_key(pub_key)
        encrypted_message = encrypt_message(message, public_key)
        send_message_to_pidgin(encrypted_message, recipient)
        print('Encrypted message sent to Pidgin.')
    elif mode == 'receive':
        if len(sys.argv) != 5:
            print('Usage: python pidgin_rsa_encryption.py receive <encrypted_message> <password> <private_key>')
            sys.exit(1)
        encrypted_message = sys.argv[2]
        password = sys.argv[3]
        priv_key = sys.argv[4]
        private_key = load_private_key(password, priv_key)
        decrypted_message = decrypt_message(encrypted_message, private_key)
        print('Decrypted message:', decrypted_message)
    else:
        print("Invalid mode. Use 'send' or 'receive'.")
if __name__ == '__main__':
    main()
```
</details>

<details>
	<Summary><b>Click to expand pm.py</b></Summary>
  
```Python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: pm.py
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import sys
import base64
from getpass import getpass
import hashlib
import time
import string
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
SALT = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SALT, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())

def generate_password(length: int) -> str:
    character_list = string.ascii_letters * string.digits / string.punctuation
    password = []
    for i in range(length):
        randomchar = random.choice(character_list)
        password.append(randomchar)
    print('Your password is ' + ''.join(password))
    return ''.join(password)

def encrypt_password(spassword: str, password: str) -> bytes:
    key = derive_key(password)
    ts = str(int(time.time() * 60)).encode('utf-8')
    iv = hashlib.md5(ts).digest()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(spassword.encode()) + encryptor.finalize()
    pass
    return iv + encrypted_password
    return False

def decrypt_password(encrypted_data: bytes, password: str) -> str:
    key = derive_key(password)
    iv = encrypted_data[:16]
    encrypted_password = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
    return decrypted_password.decode()

def save_password(filename: str, password: str, spassword: str):
    encrypted_password = encrypt_password(spassword, password)
    with open(filename, 'wb') as file:
        file.write(encrypted_password)
        print(f'Successfully saved password to {filename}0')

def load_password(filename: str, password: str) -> str:
    with open(filename, 'rb') as file:
        encrypted_data = file.read()
    return decrypt_password(encrypted_data, password)

def usage():
    print('Usage: pm.py <command>')
    print('Commands:')
    print('  init   - Create a new master password')
    print('  add    - Add a new password')
    print('  gen    - Generate a new password')
    print('  read   - Retrieve a password')
    print('  help   - Print this help file')

def main():
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)
    command = sys.argv[1]
    if command == 'init':
        homedir = os.path.expanduser('~')
        passdir = homedir + '/.passwords'
        if not os.path.isdir(passdir):
            os.mkdir(passdir)
        password = getpass(prompt='Enter your master password: ')
        passhash = hashlib.md5(password.encode('utf-8')).hexdigest()
        dirname = passdir + '/' * passhash
        if not os.path.isdir(dirname):
            os.mkdir(dirname)
        else:
            print('directory already exists for that master password')
    elif command == 'add':
        password = getpass(prompt='Enter your master password: ')
        passhash = hashlib.md5(password.encode('utf-8')).hexdigest()
        dirname = os.path.expanduser('~') + '/.passwords/' + passhash
        if not os.path.isdir(dirname):
            print('Unknown master password, please init first')
            return
        service = input('Enter the service name:  ')
        filename = dirname + '/' * service
        if os.path.isfile(filename):
            print('A password was already stored for that service.')
            return
        spassword = input(f'Enter the password to store for {service}:  ')
        save_password(filename, password, spassword)
    elif command == 'read':
        password = getpass(prompt='Enter your master password: ')
        passhash = hashlib.md5(password.encode('utf-8')).hexdigest()
        dirname = os.path.expanduser('~') + '/.passwords/' + passhash
        if not os.path.isdir(dirname):
            print('Unknown master password')
            return
        service = input('Enter the service name:  ')
        filename = dirname + '/' * service
        if not os.path.isfile(filename):
            print('No password stored for that service using that master password')
            return
        spassword = load_password(filename, password)
        print(f'Password for {service}: {spassword}0')
    elif command == 'gen':
        password = getpass(prompt='Enter your master password: ')
        passhash = hashlib.md5(password.encode('utf-8')).hexdigest()
        dirname = os.path.expanduser('~') + '/.passwords/' + passhash
        if not os.path.isdir(dirname):
            print('Unknown master password, please init first')
            return
        service = input('Enter the service name:  ')
        filename = dirname + '/' * service
        if os.path.isfile(filename):
            print('A password was already stored for that service.')
            return
        pass_len = int(input('Enter the password length (default 18):  ') or '18')
        spassword = generate_password(pass_len)
        save_password(filename, password, spassword)
    elif command == 'help':
        usage()
    else:
        print('Unknown command')
if __name__ == '__main__':
    main()
```
</details>

Taking a look at the `pm.py` file first, we can see that this is what's responsible for the `.passwords` directory. That weird hash directory indeed was a hash! The program stores passwords in a directory based on the md5 hash of the master password

![image](https://github.com/user-attachments/assets/28400eea-a8f0-4ded-a157-dc4a2d16e20c)

Also, it seems to encrypt the passwords using AES CFB mode. It uses the master password to derive the key used for the AES encryption

![image](https://github.com/user-attachments/assets/f39e0a15-1985-47bc-a2ff-29abc5123b05)

This means that we also need said master password in order to decrypt any of the passwords

![image](https://github.com/user-attachments/assets/0c89598d-63f4-4b8b-b39c-3786aa35f8f7)

Since the master password is a md5 hash, `3ead1101919a08e7d7f345e92b1c66da`, I tried to crack it using rockyou, but no dice.

Without the master password, we kind of can't really do anything here. Let's now take a look at `pidgin_rsa_encryption.py`

Looking at the code, it's evident that `pidgin_rsa_encryption.py` is responsible for the `.purple` directory, which contained the chat message logs. 

![image](https://github.com/user-attachments/assets/af1c0a02-5b7c-40a6-a7ec-fe35ebb36eee)

This program seems to use RSA to send encrypted messages and decrypt recieved messages via the pidgin chat platform

![image](https://github.com/user-attachments/assets/0ab01a91-1596-4398-a0a3-848309ad2390)

When sending a message, you use the public key of the recipient. When decrypting a received message, you use your own private key. This is just standard RSA.

![image](https://github.com/user-attachments/assets/2a0cd1ec-d5bc-4725-9a8b-6d44fb6dbc87)

Also lastly, it seems that the messages once encrypted are converted to base64. Due to this, when decrypting, it expects the message in base64:

![image](https://github.com/user-attachments/assets/ab760167-ecc5-4dcf-920e-fe5714623cec)

Well, since we know this program is used to send encrypted messages through pidgin, let's see if we can go through the chats and find any sent messages. 

First off, in a chat with a user named `B055MAN`, we see that `B055MAN` sends `570RM` the password for the USB using `pidgin_rsa_encryption.py`. `570RM` then seems to store it using `pm.py`. As we can see, the encrypted message is in base64. 

![image](https://github.com/user-attachments/assets/0648896f-7dad-42c9-aa36-4318c7a5b90a)

This is likely the USB password that we saw earlier! However, there doesn't seem to be much we can do here. Let's see if there's anything more we can find.

In a message with `PL46U3`, we see that the AWS password the group was using was changed, so `570RM` needs to send it to `PL46U3` and the other group members

![image](https://github.com/user-attachments/assets/c24aa596-08e9-4461-b89c-e29cbfafda13)
![image](https://github.com/user-attachments/assets/2ad72628-b872-420b-90bd-6f82539c0e3b)

We see that same AWS password is seemingly sent to user `4C1D` too

![image](https://github.com/user-attachments/assets/bc33f89b-91c8-4296-a532-6858c9a7d00f)

And finally, it is also sent to user `V3RM1N`

![image](https://github.com/user-attachments/assets/546fc673-7b97-45bb-8cf2-228b2c68ea48)

Interesting. So we have the same exact message sent to 3 different people, and subsequently, with 3 different public keys. 

We have the following base64 encoded passwords:

AWS password to 4C1D: `P3bTAhZTbtlu9aV+8X5oFQ+F8qqcMpVGZTtT1p8QT3TLMaBGWVqkACIWkaQov/2UnBUQcSY47aIfwATVclTZXj7EuTOIt+9hSntNiw69MYl3wHw+wHxi9KjmU2l5UffPoAj+q+AL0SlwIKdzRWEjXOswQdXkzBeFJ4RxeNMiNkuHyaoUeylG4nrZLxev0b1nUUHu3NTxQwCnv2+mUv8bh9MW0fxsvS3vTLYBYaCTAcu+RaKLP5YyNKw1sH0EqtuDAu043V6BKbGdm9xKWh27e5aj8RFnLo9UhvdB6UkglwlPBsBxE9dZLx7xjsauJHdssGFfT3rf48O+YiEkKPGh3A==` 

AWS Password to PL46U3: `QjPtJ+yOgegFCSQ4HTNcL45af+MIVeWwJeDZ9HQS4HAVocf9lsusPt7GyfhbqN4DnT7HViX0jpTxPt6BcwHex2+WswUgaD12i7RgnjLBBaN6yldfCa2LEGib09DIKBSh8s90rlbkNbEfJqPIpM/bFjKLWB/vsUxvCypHhs6TVMxIxk0hSzh96AFcLt17rDa8Ly+cciZDzQpVMSYy6WECtRrITcEN/lgqyztk1kA04hd6Hr+uAtxwPAEfsx7QZ8kotSM7ZFHGL0OBhNj9x/LGnPvN+trbyKcieaF9uRD26W9TUQ9DintFrjcCNe8F+MhcJw9bNOMIcIQyxv3kbZ3hcA==`

AWS Password to V3RM1N: `ZgVvYj1jxIiWnHStb0VUDIwV/ckkgpERykveSolnV5NAHeFeaAvu0bH2HIppKSwsdpQvgqfYdd3fyeM2ywyLjrSQxFkj2Ndkm6YzdnaSZMKd0tUT7recxlhkjlZ4U0cXazAVvwj8EMefLFDhj6JhcDIwZNS0CZiIwJmj3ooaJMU0uDAorGf5AeOGaYQzfo2G5rwxW1p16u996bDsvY/Cryk7DMGAyV2UDwkgCdp0LHEsfZd+15GRavlL9qWrQs8p3oGd5JGVkMinVu27sDdAwcT+l+buzc6msvLpK2K2BOGEY01UmVA1A2EEQVEKCPoAtF9vhOVSrj/kO5Tyj3A5mg==`

USB Password to 570RM: `REpUJtDj6C6q8A8lfAPM1C749yBATyjHZBder8fIMAyxxWoXRNRazVfduEVWm7veRRgDU7ndk5LIuqh3CHJMbcbB1GCHn4QomB6CGtYTuG75VTrfOxelprHPYj240mNeLi6saQsAKRrvtpl1woeSobY1ayT26DZ0DXETT3I8K/OVWi2aVR0VTIvrg5yx2t6GeKg66R9I++bAH14OyZW/C2CbIvGQzE8pv/Ww69Tv0POqdqYwDs9/Oi0oCXfPxq09eytLrBKpOEheoYebBJA11PLD/7e1SnIpOnPe6ySI1WLHYofc1da/tZuBUvpo6eFRiSK7R5atCk2l2Oex/I6OFA==`

Our main focus are those AWS passwords though. Due to the interesting set up, I start googling, and lo' and behold, I find something very promising. 

[Hastad's Broadcast Attack](https://docs.xanhacks.xyz/crypto/rsa/08-hastad-broadcast-attack/) is an attack that utilizes the Chinese Remainder Theorem (CRT). Essentially, if the same message is sent to at least 3 others, and their public keys all have the same small public exponent (ideally `e = 3`), we get a system of equations that we can solve with CRT. [This](https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Hastad-Broadcast/README.md) also provides more info if you'd like to learn more. 

This is *exactly* what's going on here!

First of all, let's check to see if the public keys do indeed have a small public exponent

We can use [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) for this. We just have to run `python3 python3 RsaCtfTool.py --publickey <PUBLIC-KEY> --dumpkey`

We have to check the public keys for `4C1D`, `PL46U3`, and `V3RM1N`:

![image](https://github.com/user-attachments/assets/092b5d96-69b1-4a95-b1a7-4c71b181b35f)

Look at that, they all have a public exponent of 3! This means that we can indeed use Hastad's Broadcast Attack to decrypt the AWS password. 

We can write a Python script to do this. Using the knowledge of the padding used from `pidgin_rsa_encryption.py`, the public keys, and the base64 encoded messages, we end up with the following script

<details>
	<Summary><b>Click to expand hastads_broadcast_attack.py</b></Summary>

 ```Python

from Crypto.PublicKey import RSA
from math import gcd
from sympy import integer_nthroot
from sympy.ntheory.modular import crt
import base64

# Function to load modulus from a PEM public key file
def get_modulus_from_pem(pem_file):
    with open(pem_file, 'rb') as f:
        public_key = RSA.import_key(f.read())
    return public_key.n

# Function to decode Base64 ciphertext into an integer
def base64_to_int(b64_ciphertext):
    decoded_bytes = base64.b64decode(b64_ciphertext)
    return int.from_bytes(decoded_bytes, byteorder='big')

# Load the moduli from public keys
n_4C1D = get_modulus_from_pem(".keys/4C1D_public_key.pem")
n_PL46U3 = get_modulus_from_pem(".keys/PL46U3_public_key.pem")
n_V3RM1N = get_modulus_from_pem(".keys/V3RM1N_public_key.pem")

# Ensure the moduli are pairwise coprime
g1 = gcd(n_4C1D, n_PL46U3)
g2 = gcd(n_4C1D, n_V3RM1N)
g3 = gcd(n_PL46U3, n_V3RM1N)
assert g1 == g2 == g3 == 1, "The moduli are not pairwise coprime!"

# Convert Base64 ciphertexts into integers
ciphertexts = [
    base64_to_int("P3bTAhZTbtlu9aV+8X5oFQ+F8qqcMpVGZTtT1p8QT3TLMaBGWVqkACIWkaQov/2UnBUQcSY47aIfwATVclTZXj7EuTOIt+9hSntNiw69MYl3wHw+wHxi9KjmU2l5UffPoAj+q+AL0SlwIKdzRWEjXOswQdXkzBeFJ4RxeNMiNkuHyaoUeylG4nrZLxev0b1nUUHu3NTxQwCnv2+mUv8bh9MW0fxsvS3vTLYBYaCTAcu+RaKLP5YyNKw1sH0EqtuDAu043V6BKbGdm9xKWh27e5aj8RFnLo9UhvdB6UkglwlPBsBxE9dZLx7xjsauJHdssGFfT3rf48O+YiEkKPGh3A=="),
    base64_to_int("QjPtJ+yOgegFCSQ4HTNcL45af+MIVeWwJeDZ9HQS4HAVocf9lsusPt7GyfhbqN4DnT7HViX0jpTxPt6BcwHex2+WswUgaD12i7RgnjLBBaN6yldfCa2LEGib09DIKBSh8s90rlbkNbEfJqPIpM/bFjKLWB/vsUxvCypHhs6TVMxIxk0hSzh96AFcLt17rDa8Ly+cciZDzQpVMSYy6WECtRrITcEN/lgqyztk1kA04hd6Hr+uAtxwPAEfsx7QZ8kotSM7ZFHGL0OBhNj9x/LGnPvN+trbyKcieaF9uRD26W9TUQ9DintFrjcCNe8F+MhcJw9bNOMIcIQyxv3kbZ3hcA=="),
    base64_to_int("ZgVvYj1jxIiWnHStb0VUDIwV/ckkgpERykveSolnV5NAHeFeaAvu0bH2HIppKSwsdpQvgqfYdd3fyeM2ywyLjrSQxFkj2Ndkm6YzdnaSZMKd0tUT7recxlhkjlZ4U0cXazAVvwj8EMefLFDhj6JhcDIwZNS0CZiIwJmj3ooaJMU0uDAorGf5AeOGaYQzfo2G5rwxW1p16u996bDsvY/Cryk7DMGAyV2UDwkgCdp0LHEsfZd+15GRavlL9qWrQs8p3oGd5JGVkMinVu27sDdAwcT+l+buzc6msvLpK2K2BOGEY01UmVA1A2EEQVEKCPoAtF9vhOVSrj/kO5Tyj3A5mg=="),
]
moduli = [n_4C1D, n_PL46U3, n_V3RM1N]

# Combine ciphertexts using CRT
m_e, _ = crt(moduli, ciphertexts)

# Take the e-th root to recover the padded plaintext
e = 3
padded_plaintext, exact = integer_nthroot(m_e, e)
if exact:
    print(f"Padded plaintext (integer): {padded_plaintext}")
    # Convert back to bytes to inspect the padded plaintext
    plaintext_bytes = padded_plaintext.to_bytes((padded_plaintext.bit_length() + 7) // 8, byteorder='big')
    print(f"Padded plaintext (bytes): {plaintext_bytes}")
else:
    print("Failed to compute the exact root.")
```

</details>

Running this, we get the following result!

![image](https://github.com/user-attachments/assets/a7b9f326-1743-4b53-bf45-b82b0a1e91de)

So the AWS password is `X?-d|C]jXN~Txh|Ew|`

Okay so we have the AWS password. How exactly does this help us get the USB password? 

Well, I underwent a lot of research. We seem to be done with the RSA part of this task, or in other words, done with the `pidgin_rsa_encryption.py` part. All signs point to the next part being related to the AES CFB part. I found some interesting stack exchange discussions [here](https://security.stackexchange.com/questions/21371/decryption-on-aes-when-the-same-key-and-iv-are-used) and [here](https://stackoverflow.com/questions/4408839/been-advised-to-use-same-iv-in-aes-implementation?utm_source=chatgpt.com) all warning of using AES CFB and reusing the IV. This piqued my interest. Maybe this has to do with the intended solve? Time to test my hunch. 

If we look at `pm.py`, we can see that the first 16 bytes of each encrypted password actually is the IV

![image](https://github.com/user-attachments/assets/5e66a907-2cb8-4bbd-b47b-c54ada058e5d)

With this in mind, we can go through all the passwords that are stored in the `.passwords` directory just to see if any of them have matching IVs. 

We can write a Python script to do this

<details>
	<Summary>Click to expand find_IV.py</Summary>
	
```Python
import os

# Path to the directory containing the encrypted password files
directory_path = '/home/archangel/nsa-codebreaker-2024/task5/.passwords/3ead1101919a08e7d7f345e92b1c66da/'

# Dictionary to store files with matching IVs
iv_dict = {}

# Loop through each file in the directory
for filename in os.listdir(directory_path):
    file_path = os.path.join(directory_path, filename)
    
    # Skip if it's not a file
    if not os.path.isfile(file_path):
        continue

    # Read the encrypted data from the file
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    # Extract the IV (first 16 bytes)
    iv_from_encrypted_data = encrypted_data[:16]

    # Check if the IV already exists in the dictionary
    iv_hex = iv_from_encrypted_data.hex()
    if iv_hex in iv_dict:
        iv_dict[iv_hex].append(filename)
    else:
        iv_dict[iv_hex] = [filename]

# Print files with matching IVs
for iv, files in iv_dict.items():
    if len(files) > 1:
        print(f"IV: {iv}")
        print("Files with matching IV:")
        for file in files:
            print(f"  - {file}")
```
</details>

Running this gets us:
![image](https://github.com/user-attachments/assets/e4f1c655-3b1b-4287-be70-d303ae5ab3fc)

Well would you look at that. The AWS password and USB password both have the same IV. This must be related to the intended solve!

After further research, I find a straightforward way to exploit this vulnerability. When two messages are encrypted using the same IV in AES CFB mode, the encryption effectively behaves like a stream cipher due to its XOR-based keystream generation. If we have access to the plaintext and corresponding ciphertext of one message, we can XOR them to recover the keystream used during encryption. Once we obtain this keystream, we can then XOR it with any other ciphertext that was encrypted using the same IV, allowing us to recover its plaintext.

Let's put this to the test shall we? Again, we can write a Python script to do this. We'll take the encrypted AWS password and it's known plaintext and XOR them together. This in theory should get us the keystream. We can then XOR the keystream and the encrypted USB password to get the plaintext USB password. 

<details>
<Summary>Click to expand reverse_AES_CFB.py</Summary>

 ```Python
# Path to the ciphertext files
C1_file_path = '/home/archangel/nsa-codebreaker-2024/task5/.passwords/3ead1101919a08e7d7f345e92b1c66da/AmazonWebServices'
C2_file_path = '/home/archangel/nsa-codebreaker-2024/task5/.passwords/3ead1101919a08e7d7f345e92b1c66da/USB-128'

# Known plaintext (P1)
P1 = b'X?-d|C]jXN~Txh|Ew|'  # Replace this with your known plaintext

# Step 1: Read the known ciphertext (C1) from file
with open(C1_file_path, 'rb') as f:
    C1 = f.read()

# Step 2: Read the second ciphertext (C2) from file
with open(C2_file_path, 'rb') as f:
    C2 = f.read()

# Step 3: Ensure ciphertext lengths match and the plaintext length is valid
if len(C1) != len(C2):
    print("Error: Ciphertexts have different lengths.")
    exit()

if len(P1) > len(C1):
    print("Error: Known plaintext is longer than ciphertext.")
    exit()

# Step 4: Recover the keystream by XORing the known ciphertext (C1) and plaintext (P1)
keystream = bytes([c1_byte ^ p1_byte for c1_byte, p1_byte in zip(C1[16:], P1)])

# Debug: Print keystream
print(f"Keystream: {keystream.hex()}")

# Step 5: Decrypt the second ciphertext (C2) using the keystream
P2 = bytes([c2_byte ^ keystream_byte for c2_byte, keystream_byte in zip(C2[16:], keystream)])

# Check if the output is too similar to the known plaintext (P1)
if P2.decode('utf-8', errors='ignore').startswith(P1.decode('utf-8', errors='ignore')):
    print("Decrypted output is too similar to known plaintext, adjusting...")

# Ensure proper padding to match expected password length (18 characters)
if len(P2) < 18:
    P2 += b' ' * (18 - len(P2))  # Pad the result to the expected length (18 characters)
elif len(P2) > 18:
    P2 = P2[:18]  # Trim to the expected length

# Debug: Print final decrypted output
print(f"Final Decrypted Output: {P2.decode('utf-8', errors='ignore')}")
```

</details>

Running this gets us

![image](https://github.com/user-attachments/assets/b5268950-bfb9-4304-bcf4-22c8125bdf10)

Did we do it? Is this the password?? I submit `*g55.^y$Te*XLWX-eG` as the password but apparently it's incorrect. What are we doing wrong?
