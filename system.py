import json
import pickle
import random
from math import gcd
import socket
import threading
import hashlib
from hashlib import sha256
import string
import _json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from typing import Self
from enum import Enum
import base64

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


# def encrypt(message: str, public_key):
#     # Step 1: Convert message to bytes
#     message_bytes = message.encode(FORMAT)
#
#     # Step 2: Encrypt the message
#     encrypted_bytes = [pow(b, public_key[0], public_key[1]) for b in message_bytes]
#
#     return encrypted_bytes
#
#
# def decrypt(encrypted_bytes, private_key):
#     print(type(encrypted_bytes), type(private_key))
#     # Step 1: Decrypt the message
#     print(private_key)
#     decrypted_bytes = [pow(b, private_key[0], private_key[1]) for b in encrypted_bytes]
#
#     # Step 2: Convert bytes to string
#     decrypted_message = "".join(chr(b) for b in decrypted_bytes)
#
#     return decrypted_message


class User:
    def __init__(self, email, username, password, role, salt='', hashed='', public_key='', private_key='',
                 client_listener_port=None):
        self.email = email
        self.username = username
        self.password = password
        self.salt = salt
        self.hashed = hashed
        self.role = role
        self.public_key = public_key
        self.private_key = private_key
        self.permissions = self.assign_permissions(role)
        self.client_listener_port = client_listener_port
        """
        a port that the client listens on it so that if another client 
        asks for a p2p connection we can answer it 
        """

    @staticmethod
    def assign_permissions(role: str) -> list[bool]:
        """
        role_choices = [ 'super admin' , 'admin' , 'advanced user' , 'beginner user']
        return a permission list between above users

        :param role:
        :return list:
        """
        roles_permissions = {
            Role.SUPER_ADMIN.value: [True, True, True, True],
            Role.ADMIN.value: [True, True, True, False],
            Role.ADVANCED_USER.value: [True, True, False, False],
            Role.BEGINNER_USER.value: [True, False, False, False]
        }
        return roles_permissions.get(role, [False, False, False, False])

    def __repr__(self):
        return (f"User(email={self.email}, username={self.username}, "
                f"password={self.password}, salt={self.salt}, hashed={self.hashed}, role={self.role}")

    def toJson(self):
        userModel = {
            "Email": self.email,
            "User Name": self.username,
            "Password": self.password,
            "Salt": self.salt,
            "Hash Value": self.hashed,
            "Role": self.role.value,
            "Public_key": self.public_key,
            "Private_key": self.private_key,
            "client_listener_port": self.client_listener_port
        }
        return json.dumps(userModel)

    @staticmethod
    def User_fromJson(jsonString: str) -> Self or list[Self]:
        """
        in this function we get a string with json format and make it
        into a User object or a list of User objects
        :param jsonString:
        :return:
        """
        model = json.loads(jsonString)
        if isinstance(model, list):
            users = [User(
                email=item["Email"],
                username=item["User Name"],
                password=item["Password"],
                salt=item["Salt"],
                hashed=item["Hash Value"],
                role=item["Role"],
                public_key=item["Public_key"],
                private_key=item["Private_key"],
                client_listener_port=item["client_listener_port"]
            ) for item in model]
            return users
        elif isinstance(model, dict):
            return User(
                email=model["Email"],
                username=model["User Name"],
                password=model["Password"],
                salt=model["Salt"],
                hashed=model["Hash Value"],
                role=model["Role"],
                public_key=model["Public_key"],
                private_key=model["Private_key"],
                client_listener_port=model["client_listener_port"]
            )
        # return User(model["email"], model["username"], model["password"], model["salt"], model["hashed"], model["role"])


def find_user_by_username(users, username):
    """
    search in users by username
    :param users:
    :param username:
    :return:
    """
    for user in users:
        if user.username == username:
            return user
    return None


class Key:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

    def key_toJason(self):
        key_model = {
            "Public_key": self.public_key,
            "Private_key": self.private_key
        }
        return json.dumps(key_model)

    def __repr__(self):
        return f"Key(Public_key={self.public_key}, Private_key={self.private_key}"


def key_fromJson(JsonString):
    """
    explain this function
    probably convert json string into a key object
    :param JsonString:
    :return:
    """
    model = json.loads(JsonString)
    # print(model)
    if isinstance(model, list):
        # print(model)
        keys = [Key(
            public_key=item["Public_key"],
            private_key=item["Private_key"]
        ) for item in model]
        return keys
    else:
        print(model)
        return Key(
            public_key=model["Public_key"],
            private_key=model["Private_key"]
        )
    # public_key = model["Public_key"]
    # private_key = model["Private_key"]
    # return key(
    #     public_key=model["Public_key"],
    #     private_key=model["Private_key"]
    # )


class Connection:
    def __init__(self, user_A, port_A, user_B, port_B):
        self.user_A = user_A
        self.port_A = port_A
        self.user_B = user_B
        self.port_B = port_B

    def __str__(self):
        return f"Conection username1 :{self.user_A}, userport1 : {self.port_A}, username2 :{self.user_B}, userport2 :{self.port_B}"


def generate_random_charset(length):
    # Define the character set (you can customize it as needed)
    characters = string.ascii_letters + string.digits + string.punctuation
    # Generate a random character set of the specified length
    random_charset = ''.join(random.choice(characters) for _ in range(length))
    return random_charset


class Public_keys:
    def __init__(self, username, public_key):
        """
        an object made by username and its public key
        :param username:
        :param public_key:
        """
        self.username = username
        self.pub = public_key

    def pub_toJason(self):
        pub_model = {
            "User_name": self.username,
            "Public_key": self.pub
        }
        return json.dumps(pub_model)

    def __repr__(self):
        return f"Public_keys(Username={self.username}, Pub={self.pub}"


def pub_fromJson(JsonString):
    model = json.loads(JsonString)
    # print(model)
    if isinstance(model, list):
        # print(model)
        pubs = [Public_keys(
            username=item["User_name"],
            public_key=item["Public_key"]
        ) for item in model]
        return pubs
    else:
        print(model)
        return Public_keys(
            username=model["User_name"],
            public_key=model["Public_key"]
        )


class ChatSystem:
    def __init__(self):
        self.users: list[User] = []
        """ a list of signed up users """
        self.connections: list[Connection] = []
        self.server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.server_public_key = self.server_private_key.public_key()

        # Serialize private key
        self.server_private_pem = self.server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Serialize public key
        self.server_public_pem = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # build a pem file that stores server public key
        with open('server_public_key.pem', 'wb') as f:
            f.write(self.server_public_pem)

        self.public_keys_list = []
        """
        a list of Public_keys class
        """

    def sign_up_method(self, conn) -> str:
        conn.sendall("command received".encode(FORMAT))
        new_user_data = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
        print(f"Received User info: {new_user_data}")
        new_user = User.User_fromJson(new_user_data)
        new_user.salt = generate_random_charset(8)
        salted_pass = new_user.password + str(new_user.salt)
        new_user.hashed = hashlib.sha256(salted_pass.encode(FORMAT)).hexdigest()

        # Check if the email already exists
        if any(user.email == new_user.email for user in self.users):
            conn.sendall("Email already exists. Please enter another email.".encode(FORMAT))
            # new_user.email = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
            return 'c'

        # Check if the username already exists
        elif any(user.username == new_user.username for user in self.users):
            conn.sendall("UserName already exists. Please enter another UserName.".encode(FORMAT))
            # new_user.username = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
            return 'c'
        # elif any(user.salt == new_user.salt for user in self.users):      # TODO : is this part necessary ?
        #     new_user.salt = generate_random_charset(8)
        #     conn.sendall("Wait a few minutes...".encode(FORMAT))
        #     break
        else:
            conn.sendall("Here is your key:".encode(FORMAT))
            # print(self.users, "hello")
            # public_key, private_key = generate_key_pair()
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # keys = Key(public_pem, private_pem)
            # key = str(keys)
            # user_keys = key.key_toJason()
            conn.sendall(f"{private_pem}".encode(FORMAT))
            key_arrive = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
            if key_arrive == "keys arrived":
                new_user.public_key = public_pem
                new_user.private_key = private_pem
                pub = Public_keys(new_user.username, new_user.public_key)
                self.public_keys_list.append(pub)
                print(self.public_keys_list)
                self.users.append(new_user)
                print(new_user.public_key, "helloooooo")
                # unsigned_key = str(new_user.username+ new_user.public_key)
                print(self.users[0])
                # signed = sign(unsigned_key, self.users[0].private_key)
                # conn.sendall(signed.encode(FORMAT))
                # finish = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                # if finish == "got the sign":
                #     print(public_key, private_key)
                conn.sendall("User successfully registered.".encode(FORMAT))
                new_user.public_key = public_pem
                new_user.private_key = private_pem
                # self.users.append(new_user)
                print(self.users)
                return 'b'
        return 'b'

    def login_method(self, conn, addr) -> str:
        conn.sendall("command received".encode(FORMAT))
        username = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
        password = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
        for user in self.users:
            if user.username == username:
                # Combine the entered password with the stored salt for hashing
                salted_pass = password + str(user.salt)
                # Hash the combined password and salt
                hashed = hashlib.sha256(salted_pass.encode(FORMAT)).hexdigest()
                # Check if the hashed password matches the stored hashed password
                if hashed == user.hashed:
                    conn.sendall("Login successful".encode(FORMAT))
                    # in here when we make sure that if the client logged in successfully
                    # we will set the client port too
                    user.client_listener_port = conn.recv(RECEIVE_BUFFER_SIZE)
                    # we will send the User data to client
                    conn.sendall(user.toJson().encode(FORMAT))
                    return
                else:
                    conn.sendall("Incorrect password!".encode(FORMAT))
                    return
        # conn.sendall("User not found.".encode(FORMAT))

    @staticmethod
    def decrypt_with_public_key(public_key, encrypted_data):
        return public_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def sign_with_private_key(private_key, message) -> bytes:
        signature = private_key.sign(
            message.encode('utf-8'),  # Ensure the message is in bytes
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def private_chat_method(self, conn):
        conn.sendall("command received".encode(FORMAT))
        src_username = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
        dest_username: str = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
        dest_user: User = find_user_by_username(self.users, dest_username)

        for temp_conn in self.connections:
            if (temp_conn.user_A == src_username and temp_conn.user_B == dest_username) or (
                    temp_conn.user_A == dest_username and temp_conn.user_B == src_username):
                # connection already exists
                connection = temp_conn
                break

        else:  # if for loop completed successfully ( there is no connections between these two points from before )
            if dest_user:
                print(f"Public key for user '{dest_username}': \n{dest_user.public_key}")
                conn.sendall("User is found".encode(FORMAT))
                # port_A: int = random.randint(0, 65536)    # todo : we have to delete this part and Connections class to
                # port_B: int = random.randint(0, 65536)
                #
                # all_b_ports = [x.port_B for x in self.connections]
                # all_a_ports = [x.port_A for x in self.connections]
                # all_ports = all_a_ports + all_b_ports
                #
                # ports_are_unique = False
                # while not ports_are_unique:
                #     ports_are_unique = True
                #
                #     # since all IP addresses are 'localhost' so the ports of A client and B client must be unique for their private connection
                #     if port_A in all_ports:
                #         port_A = random.randint(0, 65536)
                #         ports_are_unique = False
                #
                #     if port_B in all_ports:
                #         port_B = random.randint(0, 65536)
                #         ports_are_unique = False
                #
                # connection = Connection(src_username, port_A, dest_username, port_B)
                # self.connections.append(connection)

            else:
                print(f"User '{dest_username}' not found.")
                conn.sendall("User not found.".encode(FORMAT))
                return

        # print(connection)

        # Encrypt contact user's public key with server's private key
        signature_pub_b = ChatSystem.sign_with_private_key(private_key=self.server_private_key,
                                                           message=str(dest_user.public_key))

        dest_info = json.dumps({
            "connection_port_b": dest_user.client_listener_port,
            "public_key": dest_user.public_key
        })
        conn.sendall(signature_pub_b)  # send encrypted public key of client B
        conn.sendall(str(dest_user.public_key).encode(FORMAT))  # send encode

        return

    def handle_client(self, conn, addr):
        # server_pub, server_pri = generate_key_pair()
        print("server:", self.server_public_pem, self.server_private_pem)
        print(f"Connected by {addr}")
        self.public_keys_list.append(self.server_public_pem)
        while True:
            data = conn.recv(RECEIVE_BUFFER_SIZE)

            # first data is a blank message, so we want to
            # work with the main message, so we use below 'IF' command

            if not data:  # if data was empty
                break

            command = data.decode(FORMAT)
            print(command)

            if command == "sign up":
                break_or_continue = self.sign_up_method(conn)
                if break_or_continue == 'c':
                    continue
                return

            if command == "login":
                self.login_method(conn, addr)
                return

                # if command == "Show Users":
            # conn.sendall(str(self.users["username"]).encode(FORMAT))

            if command == "private chat":
                self.private_chat_method(conn)

    def start_server(self):
        self.public_keys_list.append(self.server_public_key)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(ADDR)
            print("[SERVER STARTED]")
            s.listen()
            print(f"Chat system listening on port {SERVER_PORT}...")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    chat_system = ChatSystem()
    chat_system.start_server()
