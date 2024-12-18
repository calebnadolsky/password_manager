import os
import getpass
import base64
from cryptography.fernet import Fernet


# Function to generate a key for encryption and decryption
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    return key


def load_key(keyfile_path="key.key"):
    if not os.path.exists(keyfile_path):
        return generate_key()
    with open(keyfile_path, "rb") as key_file:
        return key_file.read()


# Function to encrypt data
def encrypt_data(key, data):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data


# Function to decrypt data
def decrypt_data(key, encrypted_data):
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data


# Function to store a password
def store_password(service, username, password, keyfile_path="key.key"):
    key = load_key(keyfile_path)
    encrypted_password = encrypt_data(key, password)
    with open("passwords.txt", "a") as file:
        file.write(f"{service},{username},{encrypted_password.decode()}\n")
    print(f"Password for {username} at {service} stored successfully.")
    


# Function to retrieve a password
def retrieve_password(service, username, keyfile_path="key.key"):
   key = load_key(keyfile_path)
   with open("passwords.txt", "r") as file:
       for line in file.readlines():
           stored_service, stored_username, stored_encrypted_password = line.strip().split(",")
           if stored_service == service and stored_username == username: 
                decrypted_password = decrypt_data(key, stored_encrypted_password.encode())
                return decrypted_password


def main():
    while True:
        print("1. Store a Password")
        print("2. Retrieve a Password")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            service = input("Enter the service: ")
            username = input("Enter the username: ")
            password = getpass.getpass("Enter the password: ")
            store_password(service, username, password) 
        elif choice == "2":
            service = input("Enter the service: ")
            username = input("Enter the username: ")
            retrieved_password = retrieve_password(service, username)
            if retrieved_password:
                print(f"Retrieved password for {username} at {service}: {retrieved_password}")
            else:
                print("No password found for that service and username.")
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")  

if __name__ == "__main__":
    main()  
        