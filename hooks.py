class Hook:
    def __init__(self):
        self.functions = []
    def __call__(self, *args, **kwargs):
        for func in self.functions:
            r = func(*args, **kwargs)
            if r is not None:
                return r
    def register(self, func):
        self.functions.append(func)
        return func

Start1 = Hook()
Start2 = Hook()
Start3 = Hook()
Start4 = Hook()
HasPerm = Hook()