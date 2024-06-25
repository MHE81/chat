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
    def __init__(self, email, username, password, salt, hashed, role, public_key, private_key):
        self.email = email
        self.username = username
        self.password = password
        self.salt = salt
        self.hashed = hashed
        self.role = role
        self.public_key = public_key
        self.private_key = private_key
        self.permissions = self.assign_permissions(role)

    @staticmethod
    def assign_permissions(role: str) -> list[int]:
        """
        :param role:
        role_choices = [ 'super admin' , 'admin' , 'advanced user' , 'beginner user']
        :return list:
        return a permission list between above users
        """
        roles_permissions = {
            Role.SUPER_ADMIN: [True, True, True, True],
            Role.ADMIN: [True, True, True, False],
            Role.ADVANCED_USER: [True, True, False, False],
            Role.BEGINNER_USER: [True, False, False, False]
        }
        return roles_permissions.get(role, [False, False, False, False])

    def __repr__(self):
        return (f"User(email={self.email}, username={self.username}, "
                f"password={self.password}, salt={self.salt}, hashed={self.hashed}, role={self.role}")

    def toJson(self) -> str:
        userModel = {
            "Email": self.email,
            "User Name": self.username,
            "Password": self.password,
            "Salt": self.salt,
            "Hash Value": self.hashed,
            "Role": self.role,
            "Public_key": self.public_key,
            "Private_key": self.private_key
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
                private_key=item["Private_key"]
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
                private_key=model["Private_key"]
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

    def __repr__(self):
        return f"Conection(User_A{self.user_A, self.port_A, self.user_B, self.port_B}"


def generate_random_charset(length):
    # Define the character set (you can customize it as needed)
    characters = string.ascii_letters + string.digits + string.punctuation
    # Generate a random character set of the specified length
    random_charset = ''.join(random.choice(characters) for _ in range(length))
    return random_charset


class Public_keys:
    def __init__(self, username, pub):
        self.username = username
        self.pub = pub

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
            pub=item["Public_key"]
        ) for item in model]
        return pubs
    else:
        print(model)
        return Public_keys(
            username=model["User_name"],
            pub=model["Public_key"]
        )


class ChatSystem:
    def __init__(self):
        self.users = []
        self.connections = []
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

        self.public_keys_list = []

    def handle_client(self, conn, addr):
        # server_pub, server_pri = generate_key_pair()
        print("server:", self.server_public_pem, self.server_private_pem)
        print(f"Connected by {addr}")
        self.public_keys_list.append(self.server_public_pem)
        while True:
            data = conn.recv(RECEIVE_BUFFER_SIZE)

            """
            first data is a blank message so we want to 
            work with the main message so we use below 'IF' command
            """

            if not data:  # if data was empty
                break
            command = data.decode(FORMAT)
            print(command)
            if command == "sign up":
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
                    continue

                # Check if the username already exists
                elif any(user.username == new_user.username for user in self.users):
                    conn.sendall("UserName already exists. Please enter another UserName.".encode(FORMAT))
                    # new_user.username = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                    continue
                # elif any(user.salt == new_user.salt for user in self.users): # TODO : is this part necessary ?
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
                        break
                break

            if command == "login":
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
                            return
                        else:
                            conn.sendall("Incorrect password!".encode(FORMAT))
                            return
                # conn.sendall("User not found.".encode(FORMAT))
            # if command == "Show Users":
            # conn.sendall(str(self.users["username"]).encode(FORMAT))
            if command == "private chat":
                conn.sendall("command received".encode(FORMAT))
                src_username = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                contact_username = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
                user = find_user_by_username(self.users, contact_username)
                if user:
                    print(f"Public key for user '{contact_username}': \n{user.public_key}")
                    conn.sendall("User is found".encode(FORMAT))
                    port_A = random.randint(0, 65536)
                    port_B = random.randint(0, 65536)
                    for connection in self.connections:
                        if connection.port == port_A:
                            port_A = random.randint(0, 65536)
                        if connection.port == port_B:
                            port_B = random.randint(0, 65536)
                    connection = Connection(src_username, port_A, contact_username, port_B)
                    print(connection)
                    self.connections.append(connection)
                    # str_public_key = str(user.public_key)
                    en_public_key = self.server_private_key.encrypt(user.public_key, padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                                                                    )
                    # en_public_key = encrypt(str_public_key, self.server_private_key)
                    print("encrypted: ", en_public_key)
                    print(type(self.server_public_key), "type")

                    de_public_key = self.server_public_key.decrypt(
                        en_public_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    # de_public_key = decrypt(en_public_key, self.server_public_key)
                    print(de_public_key)
                    # data = pickle.dumps(self.server_pub)
                    conn.sendall(f"{en_public_key}".encode(FORMAT))
                    print(self.public_keys_list[1])
                    conn.sendall(str(self.public_keys_list[1]).encode(FORMAT))
                    # conn.sendall(f"Port:{port_A}".encode(FORMAT))
                else:
                    print(f"User '{contact_username}' not found.")
                    conn.sendall("User not found.".encode(FORMAT))

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

# def is_prime(n, k=5):
#     if n <= 1:
#         return False
#     if n <= 3:
#         return True
#     if n % 2 == 0:
#         return False
#
#     r, s = 0, n - 1
#     while s % 2 == 0:
#         r += 1
#         s //= 2
#
#     for _ in range(k):
#         a = random.randint(2, n - 2)
#         x = pow(a, s, n)
#         if x == 1 or x == n - 1:
#             continue
#         for _ in range(r - 1):
#             x = pow(x, 2, n)
#             if x == n - 1:
#                 break
#         else:
#             return False
#     return True
#
#
# def generate_large_prime(key_size):
#     # Generate a large prime number of key_size bits.
#     while True:
#         num = random.getrandbits(key_size)
#         if is_prime(num):
#             return num
#
#
# def modinv(a, m):
#     # Compute the modular inverse of a under modulo m using the Extended Euclidean Algorithm.
#     m0, x0, x1 = m, 0, 1
#     if m == 1:
#         return 0
#     while a > 1:
#         q = a // m
#         m, a = a % m, m
#         x0, x1 = x1 - q * x0, x0
#     if x1 < 0:
#         x1 += m0
#     return x1
#
#
# def generate_key_pair(key_size=128):
#     # Generate RSA public-private key pair.
#     p = generate_large_prime(key_size // 2)
#     q = generate_large_prime(key_size // 2)
#
#     n = p * q
#     phi = (p - 1) * (q - 1)
#
#     e = 65537
#     if gcd(e, phi) != 1:
#         raise ValueError("e and phi are not coprime. Please choose different primes.")
#
#     d = modinv(e, phi)
#
#     public_key = (e, n)
#     private_key = (d, n)
#
#     return public_key, private_key
