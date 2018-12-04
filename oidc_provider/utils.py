from django.core.cache import cache as dj_cache


class cache:
    """
    Cache decorator that memoizes the return value of a method for some time.
    This will not be functional for functions returning None
    """
    def __init__(self, ttl):
        self.ttl = ttl

    def __call__(self, fn):
        def wrapped(this, *args):
            cached_value = dj_cache.get(str(args))
            if cached_value is None:
                cached_value = fn(this, *args)
                dj_cache.set(str(args), cached_value, self.ttl)
            return cached_value

        return wrapped

