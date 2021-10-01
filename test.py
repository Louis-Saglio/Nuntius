import random
import string
import time
import unittest
from sever import listen
from client import main
import threading


class MyTestCase(unittest.TestCase):
    def test_something(self):
        def client_input():
            time.sleep(1)
            return "".join(random.choices(string.ascii_letters, k=10))
        address = ("127.0.0.1", 8888)
        server = threading.Thread(target=listen, args=address)
        server.start()
        client_0 = threading.Thread(
            target=main, args=(*address, lambda: "".join(random.choices(string.ascii_letters, k=10)))
        )
        client_1 = threading.Thread(
            target=main, args=(*address, lambda: "".join(random.choices(string.ascii_letters, k=10)))
        )


if __name__ == "__main__":
    unittest.main()
