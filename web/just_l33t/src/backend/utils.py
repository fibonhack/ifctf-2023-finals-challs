import string
import random

def random_string(k=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=k))
