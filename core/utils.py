import random
import string
def generate_username():
    users_alphabets = "".join(random.choices(string.ascii_lowercase, k=5))
    users_number = random.randint(00000, 99999)
    return str(users_alphabets) + str(users_number)
        