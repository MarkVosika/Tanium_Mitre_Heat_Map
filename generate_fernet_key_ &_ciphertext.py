#generate a secret key, combine password with key to generate ciphertext, and write ciphertext to a file

import getpass
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)

p = getpass.getpass("Enter base64 encoded password to generate ciphertext: ")

cipher_text = cipher_suite.encrypt(p)

print "\n\nyou entered: " + p + "\n"

print "key:"
print key + "\n"

with open('<file_name>', 'wb') as file_object:  file_object.write(cipher_text)
	