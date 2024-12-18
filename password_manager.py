import os
import getpass
import base64
import sqlite3
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

def init_db():
	conn = sqlite3.connect("password_manager.db")
	cursor = conn.cursor()
	cursor.execute("""
		CREATE TABLE IF NOT EXISTS passwords (
            id INTERGER PRIMARY KEY,
			service TEXT NOT NULL,
            username TEXT NOT NULL,
			password TEXT NOT NULL
		)
	""")
	conn.commit()
	conn.close(


# Function to store a password
def store_password(service, username, password, keyfile_path="keyu.key"):
    key = load_key(keyfile_path)
    encrypted_passwords = encrypt_data(key, password)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO passwords (service, username, password)
        VALUES (?, ?, ?)
	''', (service, username, encrypted_passwords.decode()))
    conn.commit()
    conn.close()
    print(f"Password for {username}, at {service}, stored successfully.")

    


# Function to retrieve a password
def retrieve_password(service, username, keyfile_path="key.key"):
    key = load_key(keyfile_path)
    conn = sqlite3.connect('passwords.db')
    cursor  = conn.cursor()
    cursor.execute('''
            SELECT password FROM passwords
            WHERE service = ? AND username = ?
    ''', (service, username)
    result = cursor.fetchone()
    conn.close()
    if result:
        encrypted_password = result[0]
        decrypted_password = decrypt_data(key, encrypted_password.encode())
        return decrypted_password
    return None
    



def main():
    init_db()
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
        