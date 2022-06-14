import json
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import binascii
import time
from time import perf_counter

#AES 128 encryption using CBC mode and random key and id
#converted into bytes, padded, and encoded with utf-8
#Then passed to json object to be recieved for decryption
data = input("Enter message to be encrypted: ")
key = get_random_bytes(16)
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertexts = base64.b64encode(cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))).decode('utf-8')
encryption_envelope = json.dumps({'ciphertext' : ciphertexts, 'iv' : base64.b64encode(iv).decode('utf-8')})
print(encryption_envelope)

#Loads the json with the ciphertext and iv
#Then unpads and decrypts
#prints both the encrypted ciphertext and plaintext
entry = input("Do you want to decrypt? y/n:")
if entry == "y":
    b64 = json.loads(encryption_envelope)
    ct = base64.b64decode(b64['ciphertext'])
    print(ct)
    iv = base64.b64decode(b64['iv'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size)
    print("The message was: ", plaintext)
elif entry == "n":
    print("To the next encryption method")

#RSA 2048 encryption transforms message into bytes and generates a key
#uses a private key along with a publc key
info = input("Would you like to encrypt using RSA? y/n: ")
if entry == "y":
    msg = input("Please enter message to be encrypted: ")
    #Key generation and file generation
    RSA_key = RSA.generate(2048)
    private_key = RSA_key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()
    #Publick key generation and file creation to share
    public_key = RSA_key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()
    #Message conversion to bytes and session key generation
    b = bytes(msg, 'utf-8')
    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)
    #encryption
    file_out = open("ctext.txt", "wb")
    encryptor = PKCS1_OAEP.new(recipient_key)
    encrypted = encryptor.encrypt(b)
    file_out.write(encrypted)
    file_out.close()
    print("Ciphertext: ", encrypted)

#Start of RSA decryption. Begin by opening file and importing the private key
#decryption is ran against the private key then the encrypted message.
warning = input("Would you like to decrypt using RSA? y/n: ")
if entry == "y":
    file_in = open("ctext.txt", "rb")

    private_key = RSA.import_key(open("private.pem").read())

    with open("ctext.txt", "rb") as f:
        bytes_read = f.read()
    decryptor = PKCS1_OAEP.new(private_key)
    decrypted = decryptor.decrypt(bytes_read)
    print ("Plaintext: ", decrypted)

print("Benchmark Testing of AES and RSA")
#AES encryption is based on key size and the number of rounds. In this case the key size is 16 bytes.
def AES_128_encryption(plaintext):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertexts = base64.b64encode(cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))).decode('utf-8')
    encryption_envelope = json.dumps({'ciphertext' : ciphertexts, 'iv' : base64.b64encode(iv).decode('utf-8')})
#AES encryption is based on key size and the number of rounds. In this case the key size is 24 bytes.
def AES_192_encryption(plaintext):
    key = get_random_bytes(24)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertexts = base64.b64encode(cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))).decode('utf-8')
    encryption_envelope = json.dumps({'ciphertext' : ciphertexts, 'iv' : base64.b64encode(iv).decode('utf-8')})
#AES encryption is based on key size and the number of rounds. In this case the key size is 32 bytes.
def AES_256_encryption(plaintext):
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertexts = base64.b64encode(cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))).decode('utf-8')
    encryption_envelope = json.dumps({'ciphertext' : ciphertexts, 'iv' : base64.b64encode(iv).decode('utf-8')})
#AES decryption by reading ciphertext and iv from encoded json file, unpads and decrypts ciphertext
def AES_decryption():
    b64 = json.loads(encryption_envelope)
    ct = base64.b64decode(b64['ciphertext'])
    iv = base64.b64decode(b64['iv'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size)
#Generates a key of size 1024
def RSA_1024_key():
    key = RSA.generate(1024)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()
#Generates a key of size 2048
def RSA_2048_key():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()
#Generates a key of size 4096
def RSA_4096_key():
    key = RSA.generate(4096)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()
#RSA encryption independent of key generation allowing it to be used
#with all levels of RSA encryption
def RSA_encryption(plaintext):
    b = bytes(plaintext, 'utf-8')
    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)
    
    file_out = open("ctext.txt", "wb")
    encryptor = PKCS1_OAEP.new(recipient_key)
    encrypted = encryptor.encrypt(b)
    file_out.write(encrypted)
    file_out.close()
#Function for decryption on all levels of RSA encrytption
def RSA_decryption():
    file_in = open("ctext.txt", "rb")
    private_key = RSA.import_key(open("private.pem").read())
    with open("ctext.txt", "rb") as f:
        bytes_read = f.read()
    decryptor = PKCS1_OAEP.new(private_key)
    decrypted = decryptor.decrypt(bytes_read)
#Average for the list of times recorded for encryption and decryption
def Average(lst): 
    return sum(lst) / len(lst)

secret = input("Enter 7 character message to be encoded and tested: ")
#test for AES 128
for i in range(1, 100):
    start = perf_counter()
    AES_128_encryption(secret)
    end = perf_counter()
    execution_time = (end - start)
    time = []
    time.append(execution_time)
    d_start = perf_counter()
    AES_decryption()
    d_end = perf_counter()
    execution_time = (end - start)
    d_time = []
    d_time.append(execution_time)
print("AES 128 Encryption time", Average(time))
print("AES 128 decryption time", Average(d_time))
#test for AES 192
for i in range(1, 100):
    start = perf_counter()
    AES_192_encryption(secret)
    end = perf_counter()
    execution_time = (end - start)
    time = []
    time.append(execution_time)
    d_start = perf_counter()
    AES_decryption()
    d_end = perf_counter()
    d_execution_time = (d_end - d_start)
    d_time = []
    d_time.append(d_execution_time)
print("AES 192 Encryption time", Average(time))
print("AES 192 decryption time", Average(d_time))
#test for AES 256
for i in range(1, 100):
    start = perf_counter()
    AES_256_encryption(secret)
    end = perf_counter()
    execution_time = (end - start)
    time = []
    time.append(execution_time)
    d_start = perf_counter()
    AES_decryption()
    d_end = perf_counter()
    d_execution_time = (d_end - d_start)
    d_time = []
    d_time.append(d_execution_time)
print("AES 256 Encryption time", Average(time))
print("AES 256 decryption time", Average(d_time))
#test for RSA 1024
for i in range(1, 100):
    RSA_1024_key()
    start = perf_counter()
    RSA_encryption(secret)
    end = perf_counter()
    execution_time = (end - start)
    time = []
    time.append(execution_time)
    d_start = perf_counter()
    RSA_decryption()
    d_end = perf_counter()
    d_execution_time = (d_end - d_start)
    d_time = []
    d_time.append(d_execution_time)
print("RSA 1024 Encryption time", Average(time))
print("RSA 1024 decryption time", Average(d_time))
#test for RSA 2048
for i in range(1, 100):
    RSA_2048_key()
    start = perf_counter()
    RSA_encryption(secret)
    end = perf_counter()
    execution_time = (end - start)
    time = []
    time.append(execution_time)
    d_start = perf_counter()
    RSA_decryption()
    d_end = perf_counter()
    d_execution_time = (d_end - d_start)
    d_time = []
    d_time.append(d_execution_time)
print("RSA 2048 Encryption time", Average(time))
print("RSA 2048 decryption time", Average(d_time))
#test for RSA 4096
for i in range(1, 100):
    RSA_4096_key()
    start = perf_counter()
    RSA_encryption(secret)
    end = perf_counter()
    execution_time = (end - start)
    time = []
    time.append(execution_time)
    d_start = perf_counter()
    RSA_decryption()
    d_end = perf_counter()
    d_execution_time = (d_end - d_start)
    d_time = []
    d_time.append(d_execution_time)
print("RSA 4096 Encryption time", Average(time))
print("RSA 4096 decryption time", Average(d_time))

