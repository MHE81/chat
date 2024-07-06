def add_1(inp):
    return inp + 1


x = 3

func_3 = lambda i=x: add_1(i)

x = 10
print(func_3())
