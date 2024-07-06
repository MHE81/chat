# chat
a secure socket programming private and group chat 
# secure chat

## signup and login

وقتی شما دکمه ی ثبت نام را میزنید برای بار اول کسی که ثبت نام میکند به عنوان سوپر یوزر تلقی میشود و دفعات بعدی به عنوان یوزر مبتدی که با استفاده از توابع زیر کاربر ها را میسازند 
```python
creation_is_done = client.create_super_admin(email=email,
                                             username=username,
                                             password=password,
                                             password_confirm=confirm_pass)
```

```python
message = client.sign_up(email=email,
                         username=username,
                         password=password,
                         password_confirm=confirm_pass)
```
که در متود داخلی آنها ما اول رمز و تایید رمز را چک میکنیم و سپس یک شی از نوع کاربر میسازیم و سپس آنرا تبدیل به فایل جیسون میکنیم و برای سرور میفرستیم و آنها را نیز به صورت فالش میفرستیم 

## login 
در قسمت لاگین هم ما مقدار رمز و نام کاربر را به صورت فالش به سمت سرور میفرستیم 

```python
response = client.login(username=username, password=password)
```

## private chat

### سمت کاربر فرستنده (client A) 
در این قسمت وقتی روی کلید چت خصوصی میزنیم یک صفحه ی جدید باز میشود که در آن باید نام کاربری شخص گیرنده را وارد کنیم و پیامی که میخواهیم بفرستیم

```python
def private_chat(username, client_b_username, message, is_cert=False)
```

ما در تابع بالا پیام خود و نام کاربری خود و شخص مقابل را درج میکنیم و سپس در کد ما ابتدا با سرور ارتباط میگیریم و به دنبال کلید عمومی کاربر مقابل میگردیم و پورتی که کاربر گیرنده روی آن شنود میکند
که در سمت سرور این کلید با رمز خصوصی سرور رمز شده و خود پیام امضا شده همراه با مقدار فالش آن برای ما فرستاده میشوند و ما میتوانیم آنها را ارزیابی کنیم ببینیم که آیا این پیام واقعا از سمت سرور آمده است یا خیر؟
```python
server_socket.sendall(username.encode(FORMAT))
server_socket.sendall(client_b_username.encode(FORMAT))

signature_pub_b_pem = server_socket.recv(RECEIVE_BUFFER_SIZE)
info = server_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT).split(":")
public_key_pem_user_B, client_B_listener_port = info[0], int(info[1])

authorized = ChatSystem.verify_signature(public_key=server_public_key,
                                         mess_in_byte=public_key_pem_user_B.encode(FORMAT),
                                         signature=signature_pub_b_pem)

if not authorized:
    return
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

سپس یک ارتباط جدید با سرور برقرار میکنیم و از سرور کلید عمومی کاربری که نام کاربری آنرا فرستادیم میخواهیم و سپس مقدار امضا شده ی کلید عمومی به همراه مقدار فالش آن به صورت جدا برای ما فرستاده میشود تا امضا را ارزیابی بکنیم. و وقتی ارتباط برقرار شد مانند زیر داده ها را میفرستیم.

```python
server_socket.sendall(client_A_username.encode(FORMAT))
signed_public_key = server_socket.recv(RECEIVE_BUFFER_SIZE)
server_socket.sendall("signed public key received".encode(FORMAT))
client_A_public_key_pem = server_socket.recv(RECEIVE_BUFFER_SIZE)
```

و سپس با استفاده از کلید خصوصی خود پیام را رمزگشایی کرده و با استفاده از کلید عمومی کاربر مبدا امضا را ارزیابی میکنیم.

## public chat

در چت گروهی ما ابتدا کاربرانی که قصد ایجاد گروه با آنها را داریم را وارد میکنیم و همه ی آنها را در متغیر زیر در سمت گرافیک برنامه میریزیم.

```python
entries_data = [entry.get() for entry in self.entries_pub_chat]
group_id = client.public_chat_method(user_to_add=entries_data)
```

سپس ما ابتدا مشخص میکنیم که فقط کسی حق دارد گروه بسازد که مجوز های لازم را داشته باشد.
```python
if not MyUser.permissions[1]:
    return "you can't add public chats"
```

حالا با سرور ارتباط برقرار میکنیم و تلاش میکنیم که یک چت گروهی را ایجاد کنیم.

سپس اسم یوزر ها را که در یک لیست هستند با استفاده از `,` جدا میکنیم و داخل یک رشته میریزیم و سمت دیگر آنها را با استفاده از `,` جدا میکنیم

```python
users_str = ",".join(user_to_add)
server_socket.sendall(users_str.encode(FORMAT))
```

سپس تلاش میکنیم تا پورت خودمان را بسازیم و آنرا به سرور بفرستیم و سرور آنرا میگیرد و در صورت خالی بودن پورت به ما اجازه ی استفاده از آن را میدهد.

```python
while True:
    group_port = random.randint(1024, 65535)
    server_socket.sendall(str(group_port).encode(FORMAT))
    response = server_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
    if response == "chat started":
        break
```
که البته این که شماره ی پورت چند هست و اینکه آیا اون پورت قبول شده است یا نه به صورت فالش فرستاده میشود.

حالا که همه چیز تایید شده است پیام certificate به صورت رمز شده توسط کلید خصوصی سرور همراه با اطلاعات مربوط به نام کاربر ما و پورت و آیدی گروه به صورت فالش برای ارزیابی برای ما فرستاده میشوند

```python
certificate = server_socket.recv(RECEIVE_BUFFER_SIZE)
server_socket.sendall("command received".encode(FORMAT))
data = server_socket.recv(RECEIVE_BUFFER_SIZE).decode(FORMAT)
myUsername, certificate_message = data.split("\n")
group_ID, group_port = certificate_message.split(",")
group_port = int(group_port)
authorized = ChatSystem.verify_signature(public_key=server_public_key,
                                         mess_in_byte=certificate_message.encode(FORMAT),
                                         signature=certificate)

if not authorized:
    return "Invalid signature"
```

و حالا پیام سرتیفیکیت را برای همه ی کاربر های موجود در لیست کاربران گروه با استفاده از تابع پیام خصوصی میفرستیم اما در آن مشخص میکنیم که این پیام یک پیام شخصی نیست تا کاربر مورد نظر پیام را صرفا یک دعوت در نظر بگیرد نه یک پیام از شخص 

```python
for user in user_to_add:
    private_chat(username=myUsername,
                 client_b_username=user,
                 message=certificate_message,
                 is_cert=True)
```

## create public message on server side

در سمت سرور ما همان کار هایی که متناسب با سمت کلاینت است انجام میدهیم اما نکاتی نیز در آنها وجود دارد

اول از همه که در سمت سرور ما با تابع زیر گروه را میسازیم

```python
def public_chat_method(self, conn):
```

و نکته ی دیگر این است که ما هر گاه یک گروه میسازیم اطلاعات مورد نیاز در مورد گروه را در کلاس گروه ذخیره میکنیم.

```python
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

```
```python
Groups.append(Group(group_ID=group_id, group_port=group_port, group_users=group_users))
```

و نکته ی مهم دیگر این که وقتی گروه ساخته میشود ما به سرور میگویم که همیشه روی پورت گروه شنود بکند

```python
threading.Thread(target=self.listen_to_port, args=(group_port,)).start()
```

## send message in public chat

در گروه های عمومی ما با استفاده از تابع زیر پیام خود را میفرستیم

```python
def send_public_message(message: str, group_id: str, is_command=False, is_add=None):
```

که در آن ما روی پورتی که برای گروه مشخص کردیم به سرور وصل میشویم

```python
group_port = MyUser.public_chat_ports[group_id]
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((MY_IP, group_port))
```

سپس در پیام ها اسم فرستنده را نیز اضافه میکنیم و همراه آیدی گروه آنرا توسط کلید عمومی سرور رمز میکنیم و برای سرور میفرستیم

```python
data = message + ",=" + group_id
encrypted_message = ChatSystem.encrypt_with_public_key(public_key=server_public_key,
                                                       mess_in_byte=data.encode(FORMAT))
s.sendall(encrypted_message)
```

در سمت سرور هم این اطلاعات را در کلاس گروه ذخیره میکنیم و با استفاده از آیدی گروه آنرا از بین گروه های موجود در سرور پیدا میکنیم.

## reload messages
ما هرگاه یک پیام در چت گروهی میفرستیم در واقع داریم آنرا برای سرور میفرستیم و هرگاه کسی خواست ببیند که چه پیام هایی برای او آمده است باید از ریلود برای بارگزاری پیام های موجود استفاده کند 

دلیل اینکه اینکار را کردیم این بود که شاید اگر کلاینت ها آی پی های متفاوتی میداشتند ما میتوانستیم روی یک پورت در دستگاه های متفاوت گوش کنیم ولی وقتی روی یک سیستم هستیم چند کاربر نمیتوانند همزمان به یک پورت گوش کنند.

ابتدا با استفاده از تابع زیر آنرا در هم در کلاینت و هم در سیستم فرا میخوانیم

```python
def reload_one_chat(group_id: str):
```

سپس با استفاده از پورت گروه به سرور وصل میشویم و در سمت سرور اگر هنوز در گروه باشیم میتوانیم پیام ها را بخوانیم

ابتدا آیدی گروه را با کلید عمومی سرور رمز میکنیم و انرا برای سرور میفرستیم

```python
data = group_id + ",:" + MyUser.username
encrypted_message = ChatSystem.encrypt_with_public_key(public_key=server_public_key,
                                                       mess_in_byte=data.encode(FORMAT))
server_socket.sendall(encrypted_message)
```

سپس نام کاربری خود را با کلید خصوصی خود امضا میکنیم و مقدار آنرا فالش آنرا در قسمت رمزشده به سرور فرستاده ایم و با استفاده از این دو سرور میتواند ارزیابی کند که آیا ما واقعا کسی هستیم که میگوییم یا نه

```python
signed_username = ChatSystem.sign_with_private_key(private_key=MyUser.private_key,
                                                   mess_in_byte=MyUser.username.encode(FORMAT))
server_socket.sendall(signed_username)
```

سپس سمت کاربر نیز پیام را دریافت میکند و اگر پیام بگوید که شما اجازه ی دسترسی به چت را ندارید به شما یک ارور نمایش داده میشود و نمیتوانید که ادامه ی چت ها را ببینید

# add and remove from chat

در این قسمت ما با استفاده از توابعی که با آنها پیام گروهی میفرستادیم پیام میفرستیم ولی مقدار زیر را نیز برابر با `درست` قرار میدهیم تا رفتار متفاوتی در چت ببینیم 

`is_command`
در سمت کلاینت :

```python
if is_command:
    if is_add:
        message = message + ":" + "add"
    else:
        message = message + ":" + "remove"

    message = f"{MyUser.username}" + ":" + message
```

که در واقع پیام اصلی حاوی نام کاربری کسی است که دستور اضافه یا حذف شدن آن صادر شده و خود دستور ادد یا ریموو به همراه کسی که این دستور را نیز داده به پیام اضافه میشود 


سمت سرور :
```python
if message == "add or remove client from chat":
self.store_message_from_public_chat(conn, is_command=True)
```

که در سمت سرور وقتی این دستور را میگیریم اول سطح دسترسی کلاینت را چک میکنیم و سپس به توجه به دستور آنرا از گروه حذف یا به آن اضافه میکنیم

```python
if not target_user.permissions[1]:
    conn.sendall("you can't add or remove from group chats".encode())
    return

if action == "add":
    chat_group.group_users.append(target_user)
elif action == "remove":
    chat_group.group_users.remove(target_user)
```

## add permissions

این قطعه با استفاده از کد زیر شروع میشود 
```python
def add_permissions(username: str, role_value: str):
```

در این تابع داریم:
- کاربر سوپر یوزر تغییر نقش نمیدهد
- کاربری که بیگینر یوزر است نمیتواند نقش کسی را عوض کند
- کسی که نمیتواند ادونس یوزر اضافه کند دسترسی آنرا ندارد
- کسی که نمیتواند ادمین اضافه کند دسترسی آنرا ندارد

که کاربر ها نقش های زیر را دارا هستند


    role ability :
    {
    'super admin' : can add admins , can add advanced users, can add and remove users from group chat, can send private messages
    'admin' : can can add advanced users, can add and remove users from group chat, can send private messages
    'advanced user' : can add and remove users from group chat,can send private messages
    'beginner user' : can send private messages, only this role can't create group chat
    }

سپس ما به صورت فالش نام کاربری شخص مقابل و نقشی که برای آن در نظر گرفتیم را برای سرور میفرستیم.

```python
server_socket.sendall((username + ":," + role_value).encode(FORMAT))
```

سمت سرور نیز ما با استفاده از تابع زیر نقش ها را اضافه میکنیم

```python
def add_permissions(self, conn):
```

که در آن ما صرفا نقش نام کاربری شخص مقابل را میگیریم و برای آن شخص نقش مورد نظر را تعیین میکنیم.
