import json
import random
from math import gcd
import socket
import threading
import hashlib
from hashlib import sha256
import string
import _json
# from cryptography.fernet import rsa

# def sign(message, private_key):
#     # Step 1: Hash the message
#     message_bytes = message.encode()
#     hashed_message = sha256(message_bytes.digest())
#     # Step 2: Create a sha256 hash object
#     hash_object = hashlib.sha256()
#     # Step 3: Pass the bytes to the hash object
#     hash_object.update(message_bytes)
#     # Step 4: Get the hexadecimal digest of the hash
#     hash_digest = hash_object.hexdigest()
#     # Step 5: Sign the integer
#     signature = pow(hash_digest, private_key[0], private_key[1])
#
#     # # Step 2: Convert hash to integer
#     # hashed_int = int.from_bytes(hashed_message, byteorder='big')
#     return signature


# def verify_signature(message, signature, public_key):
#     # Step 1: Hash the message
#     hashed_message = sha256(message.encode()).digest()
#
#     # Step 2: Convert hash to integer
#     hashed_int = int.from_bytes(hashed_message, byteorder='big')
#
#     # Step 3: Decrypt the signature
#     decrypted_hash = pow(signature, public_key[0], public_key[1])
#
#     # Step 4: Compare the hashes
#     return hashed_int == decrypted_hash


def encrypt(message: str, public_key):
    # Step 1: Convert message to bytes
    message_bytes = message.encode()

    # Step 2: Encrypt the message
    encrypted_bytes = [pow(b, public_key[0], public_key[1]) for b in message_bytes]

    return encrypted_bytes


def decrypt(encrypted_bytes, private_key):
    # Step 1: Decrypt the message
    decrypted_bytes = [pow(b, private_key[0], private_key[1]) for b in encrypted_bytes]

    # Step 2: Convert bytes to string
    decrypted_message = "".join(chr(b) for b in decrypted_bytes)

    return decrypted_message


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
            'super admin': [True, True, True, True],
            'admin': [True, True, True, False],
            'advanced user': [True, True, False, False],
            'beginner user': [True, False, False, False]
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
            "Role": self.role,
            "Public_key": self.public_key,
            "Private_key": self.private_key
        }
        return json.dumps(userModel)


# @staticmethod
def User_fromJson(jsonString):
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
    else:
        return User(
            email=model["Email"],
            username=model["User Name"],
            password=model["Password"],
            salt=model["Salt"],
            hashed=model["Hash Value"],
            role=model["Role"],
            public_key = model["Public_key"],
            private_key = model["Private_key"]
        )
    # return User(model["email"], model["username"], model["password"], model["salt"], model["hashed"], model["role"])


def find_user_by_username(users, username):
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


def key_fromJson(JsonString):
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
    def __init__(self, user_A, port_A, user_B, port_B ):
        self.user_A = user_A
        self.port_A = port_A
        self.user_B = user_B
        self.port_B = port_B


def generate_random_charset(length):
    # Define the character set (you can customize it as needed)
    characters = string.ascii_letters + string.digits + string.punctuation
    # Generate a random character set of the specified length
    random_charset = ''.join(random.choice(characters) for _ in range(length))
    return random_charset


class ChatSystem:
    def __init__(self):
        self.users = []
        self.connections = []
        self.server_pub, self.server_pri = generate_key_pair()

    def handle_client(self, conn, addr):
        # server_pub, server_pri = generate_key_pair()
        print(server_pub, server_pri)
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(12345)
            if not data:
                break
            command = data.decode()
            print(command)
            if command == "sign up":
                conn.sendall("command received".encode())
                new_user_data = conn.recv(12345).decode()
                print(f"Received User info: {new_user_data}")
                new_user = User_fromJson(new_user_data)
                new_user.salt = generate_random_charset(8)
                salted_pass = new_user.password + str(new_user.salt)
                new_user.hashed = hashlib.sha256(salted_pass.encode()).hexdigest()
                # print(new_user)
                # Check if the email already exists
                if any(user.email == new_user.email for user in self.users):
                    conn.sendall("Email already exists. Please enter another email.".encode())
                    # new_user.email = conn.recv(12345).decode()
                    continue
                elif any(user.username == new_user.username for user in self.users):
                    conn.sendall("UserName already exists. Please enter another UserName.".encode())
                    continue
                    # new_user.username = conn.recv(12345).decode()
                elif any(user.salt == new_user.salt for user in self.users):
                    new_user.salt = generate_random_charset(8)
                    conn.sendall("Wait a few minutes...".encode())
                    break
                else:
                    conn.sendall("Here is your key:".encode())
                    # print(self.users, "hello")
                    public_key, private_key = generate_key_pair()
                    keys = Key(public_key, private_key)
                    # key = str(keys)
                    user_keys = keys.key_toJason()
                    conn.sendall(user_keys.encode())
                    key_arrive = conn.recv(12345).decode()
                    if key_arrive == "keys arrived":
                        new_user.public_key = public_key
                        new_user.private_key = private_key
                        self.users.append(new_user)
                        print(new_user.public_key, "helloooooo")
                        # unsigned_key = str(new_user.username+ new_user.public_key)
                        print(self.users[0])
                        # signed = sign(unsigned_key, self.users[0].private_key)
                        # conn.sendall(signed.encode())
                        # finish = conn.recv(12345).decode()
                        # if finish == "got the sign":
                        #     print(public_key, private_key)
                        conn.sendall("User successfully registered.".encode())
                        new_user.public_key = public_key
                        new_user.private_key = private_key
                        # self.users.append(new_user)
                        print(self.users)
                        break
                break

            if command == "login":
                conn.sendall("command received".encode())
                username = conn.recv(12345).decode()
                password = conn.recv(12345).decode()
                for user in self.users:
                    if user.username == username:
                        # Combine the entered password with the stored salt for hashing
                        salted_pass = password + str(user.salt)
                        # Hash the combined password and salt
                        hashed = hashlib.sha256(salted_pass.encode()).hexdigest()
                        # Check if the hashed password matches the stored hashed password
                        if hashed == user.hashed:
                            conn.sendall("Login successful".encode())
                            return
                        else:
                            conn.sendall("Incorrect password!".encode())
                            return
                # conn.sendall("User not found.".encode())
            # if command == "Show Users":
                # conn.sendall(str(self.users["username"]).encode())
            if command == "private chat":
                conn.sendall("command received".encode())
                contact_username = conn.recv(12345).decode()

                user = find_user_by_username(self.users, contact_username)
                if user:
                    print(f"Public key for user '{contact_username}':\n{user.public_key}")
                    conn.sendall("User is found".encode())
                    port_A = random.randint(0, 65536)
                    port_B = random.randint(0, 65536)
                    for connection in self.connections:
                        if connection.port == port_A:
                            port_A = random.randint(0, 65536)
                        if connection.port == port_B:
                            port_B = random.randint(0, 65536)
                    connection = Connection(user.username, port_A, contact_username, port_B)
                    self.connections.append(connection)
                    str_public_key = str(user.public_key)
                    en_public_key = encrypt(str_public_key, server_pri)
                    print(en_public_key)
                    conn.sendall(f"Public key for user '{contact_username}':\n{user.public_key}\nPort:{port_A}".encode())

                else:
                    print(f"User '{contact_username}' not found.")
                    conn.sendall("User not found.".encode())

    def start_server(self):
        server_pub, server_pri = generate_key_pair()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', 12345))
            s.listen()
            print("Chat system listening on port 12345...")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()


def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(key_size):
    # Generate a large prime number of key_size bits.
    while True:
        num = random.getrandbits(key_size)
        if is_prime(num):
            return num


def modinv(a, m):
    # Compute the modular inverse of a under modulo m using the Extended Euclidean Algorithm.
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1


def generate_key_pair(key_size=512):
    # Generate RSA public-private key pair.
    p = generate_large_prime(key_size // 2)
    q = generate_large_prime(key_size // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        raise ValueError("e and phi are not coprime. Please choose different primes.")

    d = modinv(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


if __name__ == "__main__":
    chat_system = ChatSystem()
    chat_system.start_server()
