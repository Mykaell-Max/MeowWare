import time

def simple_test():
    print("This is a simple function which does absolutely nothing. Like you :)")
    time.sleep(1)
    print("Just kidding, lets go")
    return 42

def another_test():
    var = "Variable"
    exp = (23443 * 45**4) + 23412323 - 454323423 / 23123123.67
    print("This is another test function.")
    time.sleep(1)
    def inner_function():
        print("This is an inner function.")
        return 42
    time.sleep(1)
    inner_function()
    return var, exp


simple_test()
time.sleep(1)
another_test()