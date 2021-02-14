from abc import ABC, abstractmethod


class Computer(ABC):  ## abstract class, python doesnot support abstract class as java
    @abstractmethod
    def process(self):  ## abstract method
        pass


class Laptop(Computer):
    def process(self):
        print("it is running")


class Whiteboard(Computer):
    def write(self):
        print("its running")


class Programmer:
    def work(self, com):
        print("solving bugs")
        com.process()


com = Computer()

com1 = Laptop()
com2 = Whiteboard()

# com.process()
prog1 = Programmer()
prog1.work(com1)
