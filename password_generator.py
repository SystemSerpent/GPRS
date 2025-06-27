import random
from operator import length_hint

def generator(length):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()[]{}'></-=+:;,.`~"
    password = ""

    for i in range(length):
        password += random.choice(chars)

    return password

length = int(input("Password Length: "))
new_password = generator(length)
print("Your password: ", new_password)
