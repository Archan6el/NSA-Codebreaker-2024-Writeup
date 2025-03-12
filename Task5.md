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

The `.passwords` directory contains exactly that. Passwords for differnt services, but they're oddly all within a directory that looks to be a hash. Also, when we try to read any of the passwords, they seem to be encrypted

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
