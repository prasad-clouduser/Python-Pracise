
class PyCharm:
    def execute(self):
        print("compiling")
        print("Running")
class MyEditor:
    def execute(self):
        print("Spell Check")
        print("Convention Check")
        print("compiling")
        print("Running")

class Laptop:
    def code(self,ide):
        ide.execute()

#ide = PyCharm()
ide = MyEditor()

lap1 = Laptop()
lap1.code(ide)


