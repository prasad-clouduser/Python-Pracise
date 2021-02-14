class A:

    def __init__(self):
        print("in A Init")

    def feature1(self):
        print("Feature 1-A is working")

    def feature2(self):
        print("Feature 2 is working")

#class B(A):
class B:

    def __init__(self):
        #super().__init__() ## trying to call init method of class A

        print("in B Init")

    def feature3(self):
        print("Feature 1-B working")

    def feature4(self):
        print("Feature 4 working")

class C(A,B):

    def __init__(self):
        super().__init__()
        print("in C init")

    def feat(self):
        super().feature2()
## there is concept called MRO, which means it will prefer the init method the class c and then consder
# the class A from the left

a1 = C() ## it will still call A's constructor
a1.feat()
