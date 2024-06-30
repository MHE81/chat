import ast
import hashlib
import json
import random
import string

import system
from system import User, ChatSystem, key_fromJson, Key, Role
import socket
import threading
# import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from enum import Enum

FORMAT = 'utf_8'

MY_IP = 'localhost'
SERVER_PORT = 5050
ADDR = (MY_IP, SERVER_PORT)

global client_port
global MyUser
"""this is the User class that contains data of my user after we logged in"""

RECEIVE_BUFFER_SIZE = system.RECEIVE_BUFFER_SIZE

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
                user_list.extend([username, keys])
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
                elif massage == "Here is your key:":
                    keys = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                    s.sendall("keys arrived".encode(FORMAT))
                    print(keys)
                    user_list.extend([username, keys])
                    print(user_list)
                    success = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                    print(success)
                    break
            break


def private_chat(username):
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.connect(ADDR)
            server_socket.sendall("private chat".encode(FORMAT))
            receive = server_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
            if receive == "command received":
                server_socket.sendall(username.encode(FORMAT))
                contact_username = input("Chat with: ")
                server_socket.sendall(contact_username.encode(FORMAT))
                message = server_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                print(message)
                if message == "User is found":
                    signature_pub_b_pem = server_socket.recv(RECEIVE_BUFFER_SIZE)
                    info = server_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT).split(":")

                    public_key_pem_user_B, client_B_listener_port = info[0], int(info[1])

                    authorized = ChatSystem.verify_signature(public_key=server_public_key,
                                                             mess_in_byte=public_key_pem_user_B.encode(FORMAT),
                                                             signature=signature_pub_b_pem)

                    if not authorized:
                        return

                    public_key_user_B = serialization.load_pem_public_key(public_key_pem_user_B.encode(FORMAT))
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_b_socket:
                        client_b_socket.connect((MY_IP, client_B_listener_port))
                        client_b_socket.sendall("message from client A".encode(FORMAT))
                        message = input("Enter your private message: ")
                        client_b_socket.sendall(MyUser.username.encode(FORMAT))
                        # sign the message using client A's private key
                        signed_message = ChatSystem.sign_with_private_key(private_key=MyUser.private_key,
                                                                          mess_in_byte=message.encode(FORMAT))

                        # encrypt the sign message with client B's public key
                        encrypted_message = ChatSystem.encrypt_with_public_key(public_key=public_key_user_B,
                                                                               mess_in_byte=message.encode(FORMAT))

                        # send the data to client B
                        client_b_socket.sendall(encrypted_message)
                        response = client_b_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                        client_b_socket.sendall(signed_message)
                        response = client_b_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)

                        break
                elif message == "User not found.":
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
                # send listener port of client
                s.sendall(str(client_port).encode(FORMAT))
                my_user_jsonString = s.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                print(my_user_jsonString)
                MyUser = User.User_fromJson(my_user_jsonString)
                while True:
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
        command = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)

        if not command:
            break

        if command == "message from client A":
            client_A_username: str = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)

            # step 2 ask form server for client A's public key
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.connect(ADDR)
                server_socket.sendall("ask for public key".encode(FORMAT))
                respond = server_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)

                if respond != "command received":
                    print("Invalid response")
                    exit(1)

                server_socket.sendall(client_A_username.encode(FORMAT))
                signed_public_key = server_socket.recv(RECEIVE_BUFFER_SIZE)
                server_socket.sendall("signed public key received".encode(FORMAT))
                client_A_public_key_pem = server_socket.recv(RECEIVE_BUFFER_SIZE)

                authorized: bool = ChatSystem.verify_signature(public_key=server_public_key,
                                                               mess_in_byte=client_A_public_key_pem,
                                                               signature=signed_public_key)

                if authorized:
                    client_A_public_key = serialization.load_pem_public_key(client_A_public_key_pem)

            # step x decrypt with client B's private key
            encrypted_message = conn.recv(RECEIVE_BUFFER_SIZE)
            conn.sendall("message received".encode(FORMAT))
            message = ChatSystem.decrypt_with_private_key(private_key=MyUser.private_key,
                                                          encrypted_message=encrypted_message)

            # step 2 verify with client A's public key
            signed_message = conn.recv(RECEIVE_BUFFER_SIZE)
            conn.sendall("message received".encode(FORMAT))
            authorized = ChatSystem.verify_signature(public_key=client_A_public_key,
                                                     mess_in_byte=message.encode(FORMAT), signature=signed_message)

            if authorized:
                print(f" PV msg from<{client_A_username}> : {message}")
            else:
                print("we don't know if the message is from source client ( didn't authorized )")

            break


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
