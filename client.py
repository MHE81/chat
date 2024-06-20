import hashlib
import random
import string
from system import User, generate_key_pair, ChatSystem, key_fromJson, Key
import socket
import threading
# import json
# from system import encrypt, decrypt


class SignUpSystem:
    # def __init__(self):
    #     self.users = []

    @staticmethod
    def create_super_admin():
        user_list = []
        print("Super Admin:\n")
        email = input("Enter your email: ")
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        password_confirm = input("Confirm your password: ")
        # salt = generate_random_charset(8)
        # salted_pass = password + str(salt)
        # hashed = hashlib.sha256(salted_pass.encode()).hexdigest()
        role = "super admin"
        if password != password_confirm:
            print("Passwords do not match. Please try again.")
            return
        userr = User(email, username, password, "", "", role, "", "")
        useer_data = userr.toJson()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', 12345))
            s.sendall("sign up".encode())
            receive = s.recv(12345).decode()
            if receive == "command received":
                print(useer_data)
                s.sendall(useer_data.encode())
                massage = s.recv(12345).decode()
                if massage == "Here is your key:":
                    keys = s.recv(12345).decode()
                    s.sendall("keys arrived".encode())
                    # print(keys)
                    user_keys = key_fromJson(keys)
                    print(user_keys)
                    user_list.extend([username, user_keys])
                    print(user_list)
                    # signed = s.recv(12345).decode()
                    # s.sendall("got the sign".encode())
                    success = s.recv(12345).decode()
                    print(success)
        return user_list

    @staticmethod
    def sign_up():
        user_list = []
        while True:
            email = input("Enter your email: ")
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            password_confirm = input("Confirm your password: ")
            # salt = generate_random_charset(8)
            # salted_pass = password + str(salt)
            # hashed = hashlib.sha256(salted_pass.encode()).hexdigest()
            if password != password_confirm:
                print("Passwords do not match. Please try again.")
                return
            role = "begginer user"
            user_1 = User(email, username, password, "", "", role, "", "")
            useer_data = user_1.toJson()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('localhost', 12345))
                s.sendall("sign up".encode())
                receive = s.recv(12345).decode()
                if receive == "command received":
                    print(useer_data, "hello")
                    s.sendall(useer_data.encode())
                    massage = s.recv(12345).decode()
                    print(massage)
                    if massage == "Email already exists. Please enter another email.":
                        # userr.email = input("Enter your email: ")
                        # s.sendall(userr.email.encode())
                        continue
                    elif massage == "UserName already exists. Please enter another UserName.":
                        # userr.username = input("Enter your username: ")
                        # s.sendall(userr.username.encode())
                        continue
                    # keys = s.recv(12345).decode()
                    # # print(keys)
                    # user_keys = key_fromJson(keys)
                    # # print(user_keys)
                    # user_list.extend([username, user_keys])
                    # # print(user_list)
                    elif massage == "Here is your key:":
                        # print(useer_data)
                        # s.sendall(useer_data.encode())
                        keys = s.recv(12345).decode()
                        # print(keys, "hello")
                        s.sendall("keys arrived".encode())
                        # print(keys)
                        user_keys = key_fromJson(keys)
                        print(user_keys)
                        user_list.extend([username, user_keys])
                        print(user_list)
                        # signed = s.recv(12345).decode()
                        # s.sendall("got the sign".encode())
                        success = s.recv(12345).decode()
                        print(success)
                        break
                break

    def private_chat(self):
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('localhost', 12345))
                s.sendall("private chat".encode())
                receive = s.recv(12345).decode()
                if receive == "command received":
                    contact_username = str(input("Chat with: "))
                    s.sendall(contact_username.encode())
                    massage = s.recv(12345).decode()
                    print(massage)
                    if massage == "User is found":
                        contact_publickey_port = s.recv(122345).decode()
                        print(contact_publickey_port)


                    elif massage == "User not found.":
                        continue

    def login(self):
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', 12345))
            s.sendall("login".encode())
            receive = s.recv(12345).decode()
            if receive == "command received":
                s.sendall(username.encode())
                s.sendall(password.encode())
                massage = s.recv(12345).decode()
                if massage == "Login successful":
                    print(massage)
                    choice = int(input("1.Private chat\t2.Group chat\t3.Exit\n"))
                    if choice == 1:
                        SignUpSystem.private_chat(self)
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
    #         s.connect(('localhost', 12345))
    #         s.sendall("Show Users".encode())
    #         user_list = s.recv(12345).decode()
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
