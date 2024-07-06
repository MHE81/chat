import json
import pickle
import random
from cryptography.exceptions import InvalidSignature
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
import uuid

FORMAT = 'utf_8'

SERVER_IP = 'localhost'
SERVER_PORT = 5050
ADDR = (SERVER_IP, SERVER_PORT)

RECEIVE_BUFFER_SIZE = 4096 * 2


class Group:
    def __init__(self, group_ID: str, group_port: int, group_users: list):
        self.__message_history: list[str] = []
        """
        in inner list we have:\n
        0 index : username of message\n
        1st index: context of message
        """
        self.group_ID: str = group_ID
        self.group_port: int = group_port
        self.group_users: list = group_users
        self.set_message(message="----")

    def set_message(self, message: str):
        self.__message_history.append(message)

    def get_message_history(self) -> list[str]:
        return self.__message_history


Groups: list[Group] = []


class Role(Enum):
    SUPER_ADMIN = "super admin"
    ADMIN = "admin"
    ADVANCED_USER = "advanced user"
    BEGINNER_USER = "beginner user"


class User:
    def __init__(self, email: str, username: str, password: str, role: str, salt='', hashed='', public_key=' ',
                 private_key=' ',
                 client_listener_port=0, public_chat_ports={}):
        self.email = email
        self.username = username
        self.password = password
        self.salt = salt
        self.hashed = hashed
        self.role_value = role
        self.public_key = public_key
        self.private_key = private_key
        self.permissions = self.assign_permissions(role)
        """
        list_ability :
        0 : can send private messages\n
        1 : can add and remove users from group chat, can add group chat\n
        2 : can add advanced users\n
        3 : can add admins
        """
        self.private_key_pem = " "
        self.public_key_pem = " "
        if private_key != ' ':
            self.private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        self.client_listener_port: int = client_listener_port
        """
        a port that the client listens on it so that if another client 
        asks for a p2p connection we can answer it 
        """
        self.public_chat_ports: dict[str, int] = public_chat_ports
        """
        key : group id
        value : group port
        """

    @staticmethod
    def assign_permissions(role: str) -> list[bool]:
        """
        role_choices = [ 'super admin' , 'admin' , 'advanced user' , 'beginner user']
        return a permission list between above users

        list_ability :
        0 : can send private messages
        1 : can add and remove users from group chat, can add group chat
        2 : can add advanced users
        3 : can add admins

        role ability :
        {
        'super admin' : can add admins , can add advanced users, can add and remove users from group chat, can send private messages
        'admin' : can can add advanced users, can add and remove users from group chat, can send private messages
        'advanced user' : can add and remove users from group chat,can send private messages
        'beginner user' : can send private messages
        }

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
                f"password={self.password}, salt={self.salt}, hashed={self.hashed}, role={self.role_value}")

    def toJson(self):
        userModel = {
            "Email": self.email,
            "User Name": self.username,
            "Password": self.password,
            "Salt": self.salt,
            "Hash Value": self.hashed,
            "Role": self.role_value,
            "Public_key_pem": self.public_key_pem if isinstance(self.public_key_pem,
                                                                str) else self.public_key_pem.decode(FORMAT),
            "Private_key_pem": self.private_key_pem if isinstance(self.private_key_pem,
                                                                  str) else self.private_key_pem.decode(FORMAT),
            "client_listener_port": self.client_listener_port,
            "public_chat_ports": self.public_chat_ports
        }
        return json.dumps(userModel)

    @staticmethod
    def User_fromJson(jsonString: str) -> Self:
        """
        in this function we get a string with json format and make it
        into a User object
        :param jsonString:
        :return:
        """
        model = json.loads(jsonString)
        if isinstance(model, dict):
            R_pem = model["Private_key_pem"]
            U_pem = model["Public_key_pem"]
            private_key = R_pem if R_pem == " " else serialization.load_pem_private_key(R_pem.encode(FORMAT),
                                                                                        password=None)
            public_key = U_pem if U_pem == " " else serialization.load_pem_public_key(U_pem.encode(FORMAT))

            return User(email=model["Email"], username=model["User Name"], password=model["Password"],
                        role=model["Role"], salt=model["Salt"], hashed=model["Hash Value"], public_key=public_key,
                        private_key=private_key, client_listener_port=int(model["client_listener_port"]),
                        public_chat_ports=model["public_chat_ports"])


def find_user_by_username(users: list[User], username: str) -> User or None:
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

    def key_toJson(self):
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
    if isinstance(model, list):
        keys = [Key(
            public_key=item["Public_key"],
            private_key=item["Private_key"]
        ) for item in model]
        return keys
    else:
        return Key(
            public_key=model["Public_key"],
            private_key=model["Private_key"]
        )


def generate_random_charset(length):
    # Define the character set (you can customize it as needed)
    characters = string.ascii_letters + string.digits + string.punctuation
    # Generate a random character set of the specified length
    random_charset = ''.join(random.choice(characters) for _ in range(length))
    return random_charset


class Public_keys:
    def __init__(self, public_key_pem: bytes, username: str = "server"):
        """
        an object made by username and its public key
        :param username:
        :param public_key_pem:
        """
        self.username = username
        self.pub_pem: bytes = public_key_pem

    def pub_toJson(self):
        pub_model = {
            "User_name": self.username,
            "Public_key_pem": self.pub_pem.decode(FORMAT)
        }
        return json.dumps(pub_model)

    def __repr__(self):
        return f"Public_keys(Username={self.username}, Pub={self.pub_pem}"


def pub_fromJson(JsonString):
    model = json.loads(JsonString)
    if isinstance(model, list):
        pubs = [Public_keys(
            username=item["User_name"],
            public_key_pem=item["Public_key_pem"].encode(FORMAT)
        ) for item in model]
        return pubs
    else:
        return Public_keys(
            username=model["User_name"],
            public_key_pem=model["Public_key_pem"].encode(FORMAT)
        )


class ChatSystem:
    def __init__(self):
        self.users: list[User] = []
        """ a list of signed up users """
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

        self.public_keys_list: list[Public_keys] = []
        """
        a list of Public_keys class
        """

    def sign_up_method(self, conn) -> str:
        conn.sendall("command received".encode(FORMAT))
        new_user_data = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
        print(f"Received User info: {new_user_data}")
        new_user: User = User.User_fromJson(new_user_data)
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

            conn.sendall(f"{private_pem}".encode(FORMAT))
            key_arrive = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
            if key_arrive == "keys arrived":
                new_user.public_key_pem = public_pem
                new_user.private_key_pem = private_pem
                pub = Public_keys(public_key_pem=new_user.public_key_pem, username=new_user.username)
                self.public_keys_list.append(pub)
                self.users.append(new_user)
                conn.sendall("User successfully registered.".encode(FORMAT))
                new_user.public_key = public_key
                new_user.private_key = private_key
                # self.users.append(new_user)
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
                    user.client_listener_port = int(conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT))
                    # we will send the User data to client
                    conn.sendall(user.toJson().encode(FORMAT))
                    return
                else:
                    conn.sendall("Incorrect password!".encode(FORMAT))
                    return
        # conn.sendall("User not found.".encode(FORMAT))

    @staticmethod
    def encrypt_with_public_key(public_key, mess_in_byte: bytes) -> bytes:
        return public_key.encrypt(
            mess_in_byte,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_with_private_key(private_key, encrypted_message: bytes) -> str:
        return private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode(FORMAT)

    @staticmethod
    def sign_with_private_key(private_key, mess_in_byte: bytes) -> bytes:
        signature = private_key.sign(
            mess_in_byte,  # Ensure the message is in bytes
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_signature(public_key, mess_in_byte: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                mess_in_byte,  # Ensure the message is in bytes
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            print("Signature is invalid.")
            return False

    def private_chat_method(self, conn):
        conn.sendall("command received".encode(FORMAT))
        src_username = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
        conn.sendall("command received".encode(FORMAT))
        dest_username: str = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
        dest_user: User = find_user_by_username(self.users, dest_username)

        if dest_user:
            print(f"Public key for user '{dest_username}': \n{dest_user.public_key}")
            conn.sendall("User is found".encode(FORMAT))
        else:
            print(f"User '{dest_username}' not found.")
            conn.sendall("User not found.".encode(FORMAT))
            return

        # Encrypt contact user's public key with server's private key
        signature_pub_b = ChatSystem.sign_with_private_key(private_key=self.server_private_key,
                                                           mess_in_byte=dest_user.public_key_pem)
        conn.sendall(signature_pub_b)  # send encrypted public key of client B
        conn.sendall((dest_user.public_key_pem.decode(FORMAT) + ":" + str(dest_user.client_listener_port)).encode(
            FORMAT))  # send encode client B's listener port and public key's plain text

        return

    def get_public_key_by_username(self, conn, client_A_username) -> bytes or None:

        for user_key in self.public_keys_list:
            if user_key.username == client_A_username:
                print("found the public key for client A")
                return user_key.pub_pem
        else:
            print("the public key of source client didn't found")
            return None

    def send_public_key(self, conn):
        conn.sendall("command received".encode(FORMAT))
        client_A_username = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)

        public_key_pem = self.get_public_key_by_username(conn=conn, client_A_username=client_A_username)

        if public_key_pem:
            signed_public_key = ChatSystem.sign_with_private_key(private_key=self.server_private_key,
                                                                 mess_in_byte=public_key_pem)
            conn.sendall(signed_public_key)
            response = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
            if response == "signed public key received":
                conn.sendall(public_key_pem)

    def is_port_free(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return True  # Port is free
            except OSError:
                return False  # Port is in use

    def store_message_from_public_chat(self, conn, is_command=False):
        conn.sendall("command received".encode(FORMAT))
        encrypted_data = conn.recv(RECEIVE_BUFFER_SIZE)

        data = ChatSystem.decrypt_with_private_key(private_key=self.server_private_key,
                                                   encrypted_message=encrypted_data)
        message, group_id = data.split(",=")

        for t_group in Groups:
            if t_group.group_ID == group_id:
                chat_group: Group = t_group
                break

        if is_command:
            # check for the permissions
            client_username, target_username, action = message.split(":")
            client_user: User = find_user_by_username(users=self.users, username=client_username)
            target_user: User = find_user_by_username(users=self.users, username=target_username)

            if not target_user.permissions[1]:
                conn.sendall("you can't add or remove from group chats".encode())
                return

            if action == "add":
                chat_group.group_users.append(target_user)
            elif action == "remove":
                print(chat_group.group_users)
                chat_group.group_users.remove(target_user)
                print(chat_group.group_users)

        elif not is_command:

            chat_group.set_message(message=message)

        conn.sendall("done".encode(FORMAT))

    def reload_message_history(self, conn):
        conn.sendall("command received".encode(FORMAT))
        encrypted_data = conn.recv(RECEIVE_BUFFER_SIZE)
        data = ChatSystem.decrypt_with_private_key(private_key=self.server_private_key,
                                                   encrypted_message=encrypted_data)

        group_id, client_username = data.split(",:")
        conn.sendall("command received".encode(FORMAT))

        # check if the client is really who he says he is
        signature = conn.recv(RECEIVE_BUFFER_SIZE)
        client_user: User = find_user_by_username(users=self.users, username=client_username)
        client_public_key = client_user.public_key
        authorized = ChatSystem.verify_signature(public_key=client_public_key,
                                                 mess_in_byte=client_username.encode(FORMAT),
                                                 signature=signature)
        if authorized:
            conn.sendall("authorized".encode(FORMAT))
        else:
            conn.sendall("not authorized".encode(FORMAT))
            return
        _ = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)

        # find the group with group ID
        for t_group in Groups:
            # check if the user is in group
            if t_group.group_ID == group_id:
                group = t_group
                break
        message_list = group.get_message_history()

        message_history = "\n".join(message_list)

        # check if the client is in chat group or not
        if client_user in group.group_users:
            is_in_group = True
            conn.sendall(message_history.encode(FORMAT))
        else:
            is_in_group = False
            conn.sendall("you are not in the group".encode(FORMAT))



    def handle_public_chat(self, conn, addr):

        while True:
            message = conn.recv(RECEIVE_BUFFER_SIZE)

            if not message:
                break
            message = message.decode(FORMAT)
            if message == "send public message":
                self.store_message_from_public_chat(conn)
            if message == "add or remove client from chat":
                self.store_message_from_public_chat(conn, is_command=True)
            if message == "reload request":
                self.reload_message_history(conn)

            return

    def listen_to_port(self, port: int):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((SERVER_IP, port))
            print("listening on group port")
            s.listen()
            print(f"Chat system listening on port {SERVER_PORT}...")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_public_chat, args=(conn, addr)).start()

    def public_chat_method(self, conn):
        conn.sendall("command received".encode(FORMAT))
        data: str = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
        users_list: list[str] = data.split(",")
        group_owner_username = users_list[-1]
        group_owner_user = find_user_by_username(users=self.users,
                                                 username=group_owner_username)

        conn.sendall("command received".encode(FORMAT))

        # check if the port we said is empty or not

        while True:
            group_port = int(conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT))
            is_port_free: bool = self.is_port_free(group_port)
            if is_port_free:
                conn.sendall("chat started".encode(FORMAT))
                break
            else:
                conn.sendall("port is not free".encode(FORMAT))

        # find a unique group ID
        Group_IDs = [group.group_ID for group in Groups]
        while True:
            group_id = str(uuid.uuid4())
            if group_id not in Group_IDs:
                # make group object
                break
        # add users of a group
        group_users: list[User] = []
        for username in users_list:
            user = find_user_by_username(self.users, username)
            user.public_chat_ports[group_id] = group_port
            group_users.append(user)

        Groups.append(Group(group_ID=group_id, group_port=group_port, group_users=group_users))

        # send certificate combining group ID with the asked port
        certificate_message = group_id + "," + str(group_port)
        certificate = ChatSystem.sign_with_private_key(private_key=self.server_private_key,
                                                       mess_in_byte=certificate_message.encode(FORMAT))
        conn.sendall(certificate)
        _ = conn.recv(RECEIVE_BUFFER_SIZE)
        conn.sendall((group_owner_username + "\n" + certificate_message).encode(FORMAT))

        # start listening on group_port on server side so
        # if there was a message for public chat we can store it
        threading.Thread(target=self.listen_to_port, args=(group_port,)).start()

    def add_permissions(self, conn):
        conn.sendall("command received".encode(FORMAT))
        data: str = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
        username, role_value = data.split(":,")

        target_user: User = find_user_by_username(users=self.users, username=username)

        respond = "permission applied"
        if target_user.role_value == Role.SUPER_ADMIN.value:
            respond = "no one can remove super admin role"

        conn.sendall(respond.encode(FORMAT))

        target_user.role_value = role_value
        target_user.permissions = User.assign_permissions(role=role_value)

        print(target_user.permissions)

    def handle_client(self, conn, addr):
        print(f"Connected by {addr}")
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

                # if command == "Show Users":
            # conn.sendall(str(self.users["username"]).encode(FORMAT))

            if command == "private chat":
                self.private_chat_method(conn)

            if command == "ask for public key":
                self.send_public_key(conn)

            if command == "add permission to user":
                self.add_permissions(conn)

            if command == "public chat":
                self.public_chat_method(conn)

            return

    def start_server(self):
        self.public_keys_list.append(Public_keys(self.server_public_pem))

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
