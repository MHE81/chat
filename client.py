import ast
import hashlib
import random
import string
from system import User, ChatSystem, key_fromJson, Key
import socket
import threading
# import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from enum import Enum

FORMAT = 'utf_8'

SERVER_IP = 'localhost'
SERVER_PORT = 5050
ADDR = (SERVER_IP, SERVER_PORT)

RECEIVE_BUFFER_SIZE = 1024


class Role(Enum):
    SUPER_ADMIN = "super admin"
    ADMIN = "admin"
    ADVANCED_USER = "advanced user"
    BEGINNER_USER = "beginner user"


class SignUpSystem:
    # def __init__(self):
    #     self.users = []

    @staticmethod
    def create_super_admin():
        user_list = []

        while True:
            print("Super Admin:\n")
            email = input("Enter your email: ")
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            password_confirm = input("Confirm your password: ")
            role = Role.SUPER_ADMIN
            if password == password_confirm:
                print("Passwords matched. ✅")
                break

        admin_user = User(email, username, password, "", "", role, "", "")
        admin_user_data = admin_user.toJson()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(ADDR)
            s.sendall("sign up".encode(FORMAT))
            receive = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
            if receive == "command received":
                print(admin_user_data)
                s.sendall(admin_user_data.encode(FORMAT))
                massage = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                if massage == "Here is your key:":
                    keys = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                    s.sendall("keys arrived".encode(FORMAT))
                    print(keys)
                    # user_keys = key_fromJson(keys)
                    # print(user_keys)
                    user_list.extend([username, keys])
                    print(user_list)
                    # signed = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                    # s.sendall("got the sign".encode(FORMAT))
                    success = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                    print(success)
        return user_list

    @staticmethod
    def sign_up():
        user_list = []
        while True:

            while True:
                email = input("Enter your email: ")
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                password_confirm = input("Confirm your password: ")

                if password == password_confirm:  # condition to exit from signup information loop
                    print("Passwords matched. ✅")
                    break

            role = Role.BEGINNER_USER
            user_1 = User(email, username, password, "", "", role, "", "")
            useer_data = user_1.toJson()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(ADDR)
                s.sendall("sign up".encode(FORMAT))
                receive = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                if receive == "command received":
                    print(useer_data, "hello")
                    s.sendall(useer_data.encode(FORMAT))
                    massage = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                    print(massage)
                    if massage == "Email already exists. Please enter another email.":
                        # userr.email = input("Enter your email: ")
                        # s.sendall(userr.email.encode(FORMAT))
                        continue
                    elif massage == "UserName already exists. Please enter another UserName.":
                        # userr.username = input("Enter your username: ")
                        # s.sendall(userr.username.encode(FORMAT))
                        continue
                    # keys = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                    # # print(keys)
                    # user_keys = key_fromJson(keys)
                    # # print(user_keys)
                    # user_list.extend([username, user_keys])
                    # # print(user_list)
                    elif massage == "Here is your key:":
                        # print(useer_data)
                        # s.sendall(useer_data.encode(FORMAT))
                        keys = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                        # print(keys, "hello")
                        s.sendall("keys arrived".encode(FORMAT))
                        print(keys)
                        # user_keys = key_fromJson(keys)
                        # print(user_keys)
                        user_list.extend([username, keys])
                        print(user_list)
                        # signed = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                        # s.sendall("got the sign".encode(FORMAT))
                        success = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                        print(success)
                        break
                break

    def private_chat(self, username):
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(ADDR)
                s.sendall("private chat".encode(FORMAT))
                receive = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                if receive == "command received":
                    s.sendall(f"{username}".encode(FORMAT))
                    contact_username = str(input("Chat with: "))
                    s.sendall(contact_username.encode(FORMAT))
                    massage = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                    print(massage)
                    if massage == "User is found":
                        contact_publickey = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                        print(contact_publickey)
                        server_pub = eval(s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT))
                        # user_key = Key(server_pub, "")
                        print(server_pub)
                        # pub_list = [contact_publickey]

                        # server_pub.split("server public key:")
                        # print(server_pub, "ser_pub")
                        # print(type(pub_list), type(server_pub), "types")
                        # de_contact_publickey = decrypt(contact_publickey.encode(), server_pub)
                        de_contact_publickey = private_key.decrypt(
                            encrypted_message,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        print(de_contact_publickey)
                        # contact_port = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                        # print(contact_port)

                    elif massage == "User not found.":
                        continue

    def login(self):
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(ADDR)
            s.sendall("login".encode(FORMAT))
            receive = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
            if receive == "command received":
                s.sendall(username.encode(FORMAT))
                s.sendall(password.encode(FORMAT))
                massage = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                if massage == "Login successful":
                    print(massage)
                    choice = int(input("1.Private chat\t2.Group chat\t3.Exit\n"))
                    if choice == 1:
                        SignUpSystem.private_chat(SignUpSystem, username)
                    if choice == 2:
                        pass
                    if choice == 3:
                        return
                elif massage == "Incorrect password!":
                    print("Try again")
                    return

    def show_users(self):
        pass
    #     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #         s.connect(ADDR)
    #         s.sendall("Show Users".encode(FORMAT))
    #         user_list = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
    #         print(user_list["username"])

    # if not ChatSystem.users:
    #     print("No users signed up yet.")
    # else:
    #     # inp = int(input(": "))
    #     # print(self.users[inp])
    #     for user in ChatSystem.users:
    #         print(user)
    #         # print(f"Email: {user.email}, Username: {user.username}")


# Example usage:
if __name__ == "__main__":
    system = SignUpSystem()
    super_admin = system.create_super_admin()
    while True:
        action = int(input("1.Sign up\t2.Login\t 3.Show Users\t4.Exit\n"))
        if action == 1:
            system.sign_up()
        elif action == 2:
            system.login()
        elif action == 3:
            system.show_users()
        elif action == 4:
            break
        else:
            print("Invalid action.")
