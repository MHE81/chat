import tkinter as tk
from tkinter import ttk
import client
from tkinter import messagebox


class GUIApp:
    def __init__(self, root):
        self.target_username_perm = None
        self.selected_permission = None
        self.permission_listbox = None
        self.permission_window = None
        self.add_permission_button = None
        client.server_side_of_client(self)
        self.signup_window = None
        self.super_user_created: bool = False
        self.target_username_entry = None
        self.root = root
        self.root.title("secure chat")
        self.private_chat_window = None
        self.message_text = None
        self.send_button = None
        self.create_button = None
        self.cancel_button = None
        self.add_entry_button = None
        self.add_chat_button = None
        self.public_chat_button = None
        self.private_chat_button = None
        self.public_entry_frame = None
        self.public_chat_window = None

        # Frame for initial buttons
        self.button_frame = ttk.Frame(root)
        self.button_frame.grid(row=0, column=0, columnspan=4, padx=5, pady=5)

        self.signup_button = ttk.Button(self.button_frame, text="sign up", command=self.show_signup)
        self.signup_button.grid(row=0, column=0, padx=5, pady=5)

        self.login_button = ttk.Button(self.button_frame, text="Log In", command=self.show_login)
        self.login_button.grid(row=0, column=1, padx=5, pady=5)

        self.show_users_button = ttk.Button(self.button_frame, text="Show Users", command=self.show_users)
        self.show_users_button.grid(row=0, column=2, padx=5, pady=5)

        self.username_label = ttk.Label(root, text="Username")
        self.password_label = ttk.Label(root, text="Password")
        self.username_entry = ttk.Entry(root)
        self.password_entry = ttk.Entry(root, show='*')
        self.submit_button = ttk.Button(root, text="Submit", command=self.submit_credentials)

        # Frames for entries and chats
        self.entry_frame = ttk.Frame(root)
        self.chat_frame = ttk.Frame(root)

        self.entries = []
        self.text_fields = []
        self.read_only_texts = []
        self.entry_row_counter = 0  # Keep track of the row position for entries
        self.chat_row_counter = 0  # Keep track of the row position for chats

    def submit_signup(self):
        while True:
            email = self.email_entry_signup.get()
            username = self.username_entry_signup.get()
            password = self.password_entry_signup.get()
            confirm_pass = self.confirm_password_entry_signup.get()

            if not self.super_user_created:
                creation_is_done = client.create_super_admin(email=email,
                                                             username=username,
                                                             password=password,
                                                             password_confirm=confirm_pass)
                if creation_is_done:
                    self.super_user_created = True
                    break
                else:
                    messagebox.showerror("password not match", "your password and its confirmation do not match")
                    return
            elif self.super_user_created:
                message = client.sign_up(email=email,
                                         username=username,
                                         password=password,
                                         password_confirm=confirm_pass)
                if message == "Done":
                    break
                else:
                    messagebox.showerror("password not match", "your password and its confirmation do not match")
                    return
        self.signup_window.destroy()

    def show_signup(self):
        self.signup_window = tk.Toplevel(self.root)
        self.signup_window.title("sign up")

        if not self.super_user_created:
            self.signup_window.title("create super user")

        self.username_label_signup = ttk.Label(self.signup_window, text="Username")
        self.password_label_signup = ttk.Label(self.signup_window, text="Password")
        self.username_entry_signup = ttk.Entry(self.signup_window)
        self.password_entry_signup = ttk.Entry(self.signup_window, show='*')
        self.submit_button_signup = ttk.Button(self.signup_window, text="Submit", command=self.submit_signup)
        self.confirm_password_label_signup = ttk.Label(self.signup_window, text="Confirm Password")
        self.confirm_password_entry_signup = ttk.Entry(self.signup_window, show='*')
        self.email_label_signup = ttk.Label(self.signup_window, text="Email")
        self.email_entry_signup = ttk.Entry(self.signup_window)

        # Forget initial buttons instead of removing the entire frame
        self.button_frame.pack_forget()

        # Show sign up fields
        self.username_label_signup.grid(row=1, column=0, padx=5, pady=5)
        self.username_entry_signup.grid(row=1, column=1, padx=5, pady=5)

        self.email_label_signup.grid(row=2, column=0, padx=5, pady=5)
        self.email_entry_signup.grid(row=2, column=1, padx=5, pady=5)

        self.password_label_signup.grid(row=3, column=0, padx=5, pady=5)
        self.password_entry_signup.grid(row=3, column=1, padx=5, pady=5)

        self.confirm_password_label_signup.grid(row=4, column=0, padx=5, pady=5)
        self.confirm_password_entry_signup.grid(row=4, column=1, padx=5, pady=5)

        self.submit_button_signup.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    def show_login(self):

        if not self.super_user_created:
            messagebox.showerror("no Super User", "built super user first using sign up button")
            return
            # Hide initial buttons
        self.button_frame.grid_remove()

        # Show log in fields (same as sign up fields)
        self.username_label.grid(row=1, column=0, padx=5, pady=5)
        self.password_label.grid(row=2, column=0, padx=5, pady=5)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        self.submit_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def show_users(self):
        # Create a new window (Toplevel) for showing users
        self.user_window = tk.Toplevel(self.root)
        self.user_window.title("User List")

        # Add a text widget to display users
        users_text = tk.Text(self.user_window, height=10, width=40)
        users_text.insert(tk.END, "User A\nUser B\nUser C")  # Example user list
        users_text.config(state='disabled')  # Make the text read-only
        users_text.pack(padx=10, pady=10)

        # Add a close button to close the user window
        close_button = ttk.Button(self.user_window, text="Close", command=self.user_window.destroy)
        close_button.pack(pady=10)

    def choose_role(self):
        selected_index = self.permission_listbox.curselection()
        if selected_index:
            selected_item = self.permission_listbox.get(selected_index)
            target_username = self.target_username_perm.get()
            respond = client.add_permissions(username=target_username, role_value=selected_item)
            messagebox.showinfo(title="Success", message=f"{target_username} has {selected_item} role now !")


    def add_permission(self):
        self.permission_window = tk.Toplevel(self.root)
        self.permission_window.title("Add Permissions")
        self.permission_window.geometry("400x300+100+100")

        # اضافه کردن برچسب به ورودی Entry
        label_username = ttk.Label(self.permission_window, text="Target Username:")
        label_username.grid(row=0, column=0, padx=5, pady=5)

        self.target_username_perm = ttk.Entry(self.permission_window)
        self.target_username_perm.grid(row=0, column=1, padx=5, pady=5)

        # تنظیم Listbox برای نمایش لیست دسترسی‌ها
        self.permission_listbox = tk.Listbox(self.permission_window, selectmode=tk.SINGLE)
        self.permission_listbox.grid(row=1, column=0, pady=20, padx=20, columnspan=2)  # columnspan برای ادغام در دو ستون

        for role in client.Role:
            self.permission_listbox.insert(tk.END, role.value)

        # تنظیم دکمه برای نمایش آیتم انتخاب شده
        self.selected_permission = tk.Button(self.permission_window, text="Show Selected Items", command=self.choose_role)
        self.selected_permission.grid(row=2, column=0, columnspan=2, pady=10)

    def submit_credentials(self):

        username = self.username_entry.get()
        password = self.password_entry.get()

        response = client.login(username=username, password=password)
        if response != "Login successful":
            messagebox.showerror("password incorrect", "your password is incorrect")
            return

        self.root.title(f"user: {username}")
        print(f"Username: {username}, Password: {password}")

        # Hide sign up fields
        self.username_label.grid_remove()
        self.password_label.grid_remove()
        self.username_entry.grid_remove()
        self.password_entry.grid_remove()
        self.submit_button.grid_remove()

        # Show main buttons frame
        self.button_frame.grid(row=0, column=0, columnspan=4, padx=5, pady=5)

        # Show add entry button and other buttons
        self.private_chat_button = ttk.Button(self.button_frame, text="Private Chat", command=self.open_private_chat)
        self.private_chat_button.grid(row=0, column=0, padx=5, pady=5)

        self.public_chat_button = ttk.Button(self.button_frame, text="Public Chat", command=self.open_public_chat)
        self.public_chat_button.grid(row=0, column=1, padx=5, pady=5)

        self.add_permission_button = ttk.Button(self.button_frame, text="Add permission", command=self.add_permission)
        self.add_permission_button.grid(row=0, column=3, padx=5, pady=5)

        # Display frames
        self.entry_frame.grid(row=2, column=0, padx=5, pady=5, sticky='nw')
        self.chat_frame.grid(row=2, column=3, padx=5, pady=5, sticky='ne')

    def add_entry(self, message="", target_username="", response_msg="") -> bool:

        # اضافه کردن label جدید
        label = ttk.Label(self.entry_frame, text=target_username)
        label.grid(row=self.entry_row_counter, column=0, padx=5, pady=5)

        entry = ttk.Entry(self.entry_frame)
        entry.grid(row=self.entry_row_counter, column=1, padx=5, pady=5)
        entry.insert(0, message)
        entry.grid_remove()  # Hide initially
        self.entries.append(entry)

        text_field = ttk.Entry(self.entry_frame)
        text_field.grid(row=self.entry_row_counter, column=2, padx=5, pady=5)
        text_field.insert(0, response_msg)
        text_field.grid_remove()
        self.text_fields.append(text_field)

        # send_button = ttk.Button(self.entry_frame, text="Send",
        #                          command=lambda i=len(self.entries) - 1: self.send_message(i))
        # send_button.grid(row=self.entry_row_counter, column=3, padx=5, pady=5)
        # send_button.grid_remove()
        # self.send_buttons.append(send_button)

        self.root.after(0, self.show_and_fill_entry, len(self.entries) - 1, str(len(self.entries)))
        self.entry_row_counter += 1

        return True

    def add_chat(self):
        chat_frame = ttk.Frame(self.chat_frame)
        chat_frame.grid(row=self.chat_row_counter, column=0, padx=5, pady=5, sticky='w')

        read_only_text = tk.Text(chat_frame, height=4, width=30)
        read_only_text.grid(row=0, column=0, padx=5, pady=5, sticky='w')
        read_only_text.insert(tk.END, "Read-Only Text")
        read_only_text.config(state='disabled')  # Make the text field read-only

        # Add scrollbar to text field
        scrollbar = ttk.Scrollbar(chat_frame, orient="vertical", command=read_only_text.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        read_only_text.config(yscrollcommand=scrollbar.set)

        self.read_only_texts.append(read_only_text)
        self.chat_row_counter += 1

    def show_and_fill_entry(self, index, number):
        self.entries[index].grid()  # Show the entry
        # self.entries[index].insert(0, number)
        self.entries[index].config(state='readonly')  # Make the entry unchangeable
        self.text_fields[index].grid()

    # def send_message(self, index):
    #     number = self.entries[index].get()
    #     message = self.text_fields[index].get()
    #     self.text_fields[index].config(state='readonly')  # Make the text field unchangeable

    def open_private_chat(self):
        self.private_chat_window = tk.Toplevel(self.root)
        self.private_chat_window.title("Private Chat")

        # Create label and entry widgets
        target_username_label = ttk.Label(self.private_chat_window, text="message to :")
        target_username_label.grid(row=0, column=0, padx=5, pady=5)

        self.target_username_entry = ttk.Entry(self.private_chat_window)
        self.target_username_entry.grid(row=0, column=1, padx=5, pady=5)

        label_message = ttk.Label(self.private_chat_window, text="Enter your message:")
        label_message.grid(row=1, column=0, padx=5, pady=5)

        self.message_text = tk.Text(self.private_chat_window, height=10, width=40)
        self.message_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        self.send_button = ttk.Button(self.private_chat_window, text="Send", command=self.send_private_message)
        self.send_button.grid(row=3, column=0, padx=5, pady=5)

        self.cancel_button = ttk.Button(self.private_chat_window, text="Cancel",
                                        command=self.private_chat_window.destroy)
        self.cancel_button.grid(row=3, column=1, padx=5, pady=5)

    def send_private_message(self):
        message = self.message_text.get("1.0", tk.END).strip()
        username = self.target_username_entry.get()
        response_msg = client.private_chat(username=self.username_entry.get(),
                                           client_b_username=username,
                                           message=message)

        self.add_entry(message=message,
                       target_username="to: " + username,
                       response_msg=response_msg)

        self.private_chat_window.destroy()

    def open_public_chat(self):
        self.public_chat_window = tk.Toplevel(self.root)
        self.public_chat_window.title("Public Chat")

        self.add_entry_button = ttk.Button(self.public_chat_window, text="Add Entry", command=self.add_public_entry)
        self.add_entry_button.grid(row=0, column=0, padx=5, pady=5)

        self.create_button = ttk.Button(self.public_chat_window, text="Create", command=self.create_public_chat)
        self.create_button.grid(row=0, column=1, padx=5, pady=5)

        self.cancel_button = ttk.Button(self.public_chat_window, text="Cancel", command=self.public_chat_window.destroy)
        self.cancel_button.grid(row=0, column=2, padx=5, pady=5)

        self.public_entry_frame = ttk.Frame(self.public_chat_window)
        self.public_entry_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

    def add_public_entry(self):
        entry = ttk.Entry(self.public_entry_frame)
        entry.grid(row=self.entry_row_counter, column=0, padx=5, pady=5)
        self.entries.append(entry)
        self.entry_row_counter += 1

    def create_public_chat(self):
        entries_data = [entry.get() for entry in self.entries]
        print(f"Public chat entries: {entries_data}")
        self.public_chat_window.destroy()
        self.add_chat()


def start_GUI():
    root = tk.Tk()
    app = GUIApp(root)
    root.mainloop()

# start_GUI()
