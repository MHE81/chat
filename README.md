# chat
a secure socket programming private and group chat 
# secure chat

## private chat

### سمت کاربر فرستنده (client A) 
در این قسمت وقتی روی کلید چت خصوصی میزنیم یک صفحه ی جدید باز میشود که در آن باید نام کاربری شخص گیرنده را وارد کنیم و پیامی که میخواهیم بفرستیم

```python
def private_chat(username, client_b_username, message, is_cert=False)
```

ما در تابع بالا پیام خود و نام کاربری خود و شخص مقابل را درج میکنیم و سپس در کد ما ابتدا با سرور ارتباط میگیریم و به دنبال کلید عمومی کاربر میگردیم و پورتی که کاربر گیرنده روی آن میشنود که در کد زیر نحون ی کار با آنها نمایش داده شده است

```python
signature_pub_b_pem = server_socket.recv(RECEIVE_BUFFER_SIZE)
info = server_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT).split(":")

public_key_pem_user_B, client_B_listener_port = info[0], int(info[1])

authorized = ChatSystem.verify_signature(public_key=server_public_key,
                                         mess_in_byte=public_key_pem_user_B.encode(FORMAT),
                                         signature=signature_pub_b_pem)
```

سپس در ادامه به پورت کلاینت مد نظر وصل میشویم

```python
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_b_socket:
    client_b_socket.connect((MY_IP, client_B_listener_port))
```
و سپس پیام را امضا کرده و میفرستیم و همچنین پیام را رمزگذاری کرده و میفرستیم که در سمت مقابل پیام رمزنگاری شده را باز کرده و با پیام امضا شده برای تشخیص امضا مقایسه میکنیم و همچنین مواظب هستیم که پیام را به صورت فالش نفرستیم

```python
signed_message = ChatSystem.sign_with_private_key(private_key=MyUser.private_key,
                                                                          mess_in_byte=message.encode(FORMAT))

# encrypt message with client B's public key
encrypted_message = ChatSystem.encrypt_with_public_key(public_key=public_key_user_B,
                                                       mess_in_byte=message.encode(FORMAT))

# send the data to client B
client_b_socket.sendall(encrypted_message)
response = client_b_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
client_b_socket.sendall(signed_message)
```
و در ادامه هم همین کار ها را برای گرفتن پیام برگشت از سمت مقابل انجام میدهیم.

### سمت کلاینت گیرنده (client B)
در سمت مقابل یعنی در قسمت کاربر مقصد ما ابتدا نام کاربر شخص مقابل را دریافت میکنیم

```python
client_A_username = conn.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
```

سپس یک ارتباط جدید با سرور برقرار میکنیم و از سرور کلید عمومی کاربری که نام کاربری آنرا فرستادیم میخواهیم و سپس مقدار امضا شده ی کلید عمومی به همراه مقدار فالش آن به صورت جدا برای ما فرستاده میشود تا امضا را ارزیابی بکنیم.

```python
server_socket.sendall(client_A_username.encode(FORMAT))
signed_public_key = server_socket.recv(RECEIVE_BUFFER_SIZE)
server_socket.sendall("signed public key received".encode(FORMAT))
client_A_public_key_pem = server_socket.recv(RECEIVE_BUFFER_SIZE)
```

و سپس با استفاده از کلید خصوصی خود پیام را رمزگشایی کرده و با استفاده از کلید عمومی کاربر مبدا امضا را ارزیابی میکنیم.