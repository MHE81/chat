import tkinter as tk
from tkinter import ttk


class NumberApp:
    def __init__(self, root):
        self.additional_entry = None
        self.root = root
        self.root.title("Number Entry with Messages")
        self.private_chat_window = None
        self.message_text = None
        self.send_button = None
        self.create_button = None
        self.cancel_button = None
        self.add_entry_button = None
        self.logout_button = None
        self.add_chat_button = None
        self.public_chat_button = None
        self.private_chat_button = None
        self.public_entry_frame = None
        self.public_chat_window = None

        # Frame for initial buttons
        self.button_frame = ttk.Frame(root)
        self.button_frame.grid(row=0, column=0, columnspan=4, padx=5, pady=5)

        self.signin_button = ttk.Button(self.button_frame, text="Sign In", command=self.show_signin)
        self.signin_button.grid(row=0, column=0, padx=5, pady=5)

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
        self.send_buttons = []
        self.read_only_texts = []
        self.entry_row_counter = 0  # Keep track of the row position for entries
        self.chat_row_counter = 0  # Keep track of the row position for chats

    def show_signin(self):
        # Hide initial buttons
        self.button_frame.grid_remove()

        # Show sign in fields
        self.username_label.grid(row=1, column=0, padx=5, pady=5)
        self.password_label.grid(row=2, column=0, padx=5, pady=5)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        self.submit_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def show_login(self):
        # Hide initial buttons
        self.button_frame.grid_remove()

        # Show log in fields (same as sign in fields)
        self.username_label.grid(row=1, column=0, padx=5, pady=5)
        self.password_label.grid(row=2, column=0, padx=5, pady=5)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        self.submit_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def show_users(self):
        # Placeholder for showing users functionality
        print("Show users functionality not implemented yet.")

    def submit_credentials(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        print(f"Username: {username}, Password: {password}")

        # Hide sign in/log in fields
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

        self.logout_button = ttk.Button(self.button_frame, text="Logout")
        self.logout_button.grid(row=0, column=2, padx=5, pady=5)

        # self.add_entry_button = ttk.Button(self.root, text="Add Entry", command=self.add_entry)
        # self.add_entry_button.grid(row=1, column=0, padx=5, pady=5)

        self.add_chat_button = ttk.Button(self.root, text="Add Chat", command=self.add_chat)
        self.add_chat_button.grid(row=1, column=3, padx=5, pady=5)

        # Display frames
        self.entry_frame.grid(row=2, column=0, padx=5, pady=5, sticky='nw')
        self.chat_frame.grid(row=2, column=3, padx=5, pady=5, sticky='ne')

    def add_entry(self, message="", response_msg=""):
        entry = ttk.Entry(self.entry_frame)
        entry.grid(row=self.entry_row_counter, column=0, padx=5, pady=5)
        entry.insert(0, message)
        entry.grid_remove()  # Hide initially
        self.entries.append(entry)

        text_field = ttk.Entry(self.entry_frame)
        text_field.grid(row=self.entry_row_counter, column=1, padx=5, pady=5)
        text_field.insert(0, response_msg)
        text_field.grid_remove()
        self.text_fields.append(text_field)

        send_button = ttk.Button(self.entry_frame, text="Send",
                                 command=lambda i=len(self.entries) - 1: self.send_message(i))
        send_button.grid(row=self.entry_row_counter, column=2, padx=5, pady=5)
        send_button.grid_remove()
        self.send_buttons.append(send_button)

        self.root.after(0, self.show_and_fill_entry, len(self.entries) - 1, str(len(self.entries)))
        self.entry_row_counter += 1

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
        self.send_buttons[index].grid()

    def send_message(self, index):
        number = self.entries[index].get()
        message = self.text_fields[index].get()
        print(f"Message for number {number}: {message}")
        self.text_fields[index].config(state='readonly')  # Make the text field unchangeable

    def open_private_chat(self):
        self.private_chat_window = tk.Toplevel(self.root)
        self.private_chat_window.title("Private Chat")

        # Create label and entry widgets
        label_additional_info = ttk.Label(self.private_chat_window, text="Additional Information:")
        label_additional_info.grid(row=0, column=0, padx=5, pady=5)

        self.additional_entry = ttk.Entry(self.private_chat_window)
        self.additional_entry.grid(row=0, column=1, padx=5, pady=5)

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
        self.add_entry(message=message)
        if message:
            print(f"Private message sent: {message}")
            self.private_chat_window.destroy()

    def open_public_chat(self):
        self.public_chat_window = tk.Toplevel(self.root)
        self.public_chat_window.title("Public Chat")

        self.entries = []  # To keep track of entry widgets in public chat
        self.entry_row_counter = 0  # Reset counter for entries in public chat

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


if __name__ == "__main__":
    root = tk.Tk()
    app = NumberApp(root)
    root.mainloop()
