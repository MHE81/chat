def process_object(obj):
    # اینجا می‌توانید هر عملیاتی روی obj انجام دهید
    print("Processing object with data:", obj.data)

class MyClass:
    def __init__(self, data):
        self.data = data
        process_object(self)  # ارسال خود شئ به تابع process_object خارجی

def main():
    obj = MyClass("Hello, World!")
    # در این حالت، هنگامی که شئ obj ایجاد می‌شود، به طور خودکار تابع __init__ فراخوانی می‌شود و این تابع به تابع process_object ارسال می‌شود.

if __name__ == "__main__":
    main()
