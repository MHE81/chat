class Group:
    def __init__(self, group_ID: str, group_port: int):
        self._message: dict[str, str] = {}
        """
        key: username of message\n
        value: context of message
        """
        self.message_history: list[dict[str, str]] = []
        self.group_ID: str = group_ID
        self.group_port: int = group_port

    @property
    def message(self):
        return self._message

    @message.setter
    def message(self, new_message: dict[str, str]):
        self._message = new_message
        self.message_history.append(new_message)

# استفاده از کلاس
group = Group("G1", 8080)
group.message = {"user1": "Hello, world!"}
group.message = {"user2": "Hello, شسیworld!"}

print(group.message)
print(group.message_history)
