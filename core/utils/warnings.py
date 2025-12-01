import warnings

def ignore_deprecation(func):
    def wrapper(*args, **kwargs):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            func(*args, **kwargs)
    return wrapper