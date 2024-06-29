import ast
import hashlib
import json
import random
import string
from system import User, ChatSystem, key_fromJson, Key, Role
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

global client_port
global MyUser
"""this is the User class that contains data of my user after we logged in"""

RECEIVE_BUFFER_SIZE = 4096

with open('server_public_key.pem', 'rb') as f:
    server_public_key = serialization.load_pem_public_key(f.read())


def create_super_admin():
    user_list = []

    while True:
        print("Super Admin:\n")
        email = input("Enter your email: ")
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        password_confirm = input("Confirm your password: ")
        role = Role.SUPER_ADMIN.value
        if password == password_confirm:
            print("Passwords matched. ✅")
            break
        print("password does not matched ❌")

    admin_user = User(email=email, username=username, password=password, role=role)
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


def sign_up():
    global client_port
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
            else:
                print("------<<<<Passwords didn't matched try again >>>>------")

        role = Role.BEGINNER_USER.value
        user_1 = User(email=email, username=username, password=password, role=role)
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


def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(FORMAT),  # Ensure the message is in bytes
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
        return True
    except InvalidSignature:
        print("Signature is invalid.")
        return False


def private_chat(username):
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(ADDR)
            s.sendall("private chat".encode(FORMAT))
            receive = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
            if receive == "command received":
                s.sendall(username.encode(FORMAT))
                contact_username = str(input("Chat with: "))
                s.sendall(contact_username.encode(FORMAT))
                massage = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                print(massage)
                if massage == "User is found":
                    signature_pub_b = s.recv(RECEIVE_BUFFER_SIZE)
                    print(signature_pub_b)
                    info = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT).split(":")
                    public_key_user_B, client_B_listener_port = info[0], info[1]

                    authorized = verify_signature(public_key=server_public_key,
                                                  message=public_key_user_B,
                                                  signature=signature_pub_b)

                    if not authorized:
                        print("Invalid signature")
                        return
                    print("done")
                    # todo : we had to communicate with client B in this part

                elif massage == "User not found.":
                    continue


def login():
    global client_port
    global MyUser
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
                # send listener port of client
                s.sendall(str(client_port).encode(FORMAT))
                myuser_jsonString = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                print(myuser_jsonString)
                MyUser = User.User_fromJson(myuser_jsonString)
                choice = int(input("1.Private chat\t2.Group chat\t3.Exit\n"))
                if choice == 1:
                    private_chat(username)
                if choice == 2:
                    pass
                if choice == 3:
                    return
            elif massage == "Incorrect password!":
                print("Try again")
                return


def show_users():
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


def p2p_client(conn, addr):
    """
    in here we will describe to how to communicate with other client as server client
    :param conn:
    :param addr:
    :return:
    """

    # step 1: get encrypted signed message
    while True:
        encryped_message = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)

        if not message:
            break

        # step 2 ask form server for client A's public key
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(ADDR)

        # step x decrypt with client B's private key

        # step x+1 verify with client A's public key


def server_side_of_client():
    global client_port

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                client_port = random.randint(0, 65536)
                s.bind(('localhost', client_port))
                print(f"[Client listening on port {client_port}]")
                s.listen()
                while True:
                    conn, addr = s.accept()
                    threading.Thread(target=p2p_client, args=(conn, addr)).start()
        except socket.error as e:
            if e.errno == socket.errno.EADDRINUSE:
                print(f"Port {client_port} is already in use.")
            elif e.errno == socket.errno.EACCES:
                print(f"Permission denied to bind to port {client_port}.")
                return
            else:
                print(f"Failed to bind socket: {e}")


def client_and_server_actions():
    while True:
        action = int(input("1.Sign up\t2.Login\t 3.Show Users\t4.Exit\n"))
        if action == 1:
            sign_up()
        elif action == 2:
            login()
        elif action == 3:
            show_users()
        elif action == 4:
            break
        else:
            print("Invalid action.")


# Example usage:
if __name__ == "__main__":
    super_admin = create_super_admin()

    threading.Thread(target=server_side_of_client).start()
    client_and_server_actions()
