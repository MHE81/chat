import tkinter as tk
from tkinter import messagebox

def show_error():
    messagebox.showerror("خطا", "پیام خطا: عملیات ناموفق بود.")

# ساختن پنجره اصلی
root = tk.Tk()
root.title("نمایش پنجره خطا")

# ایجاد دکمه برای نمایش پیام خطا
button = tk.Button(root, text="نمایش خطا", command=show_error)
button.pack(pady=20)

# اجرای حلقه‌ی رویدادها
root.mainloop()
