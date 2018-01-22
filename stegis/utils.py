


def sublists(l, n):
    """Yield successive n-sized lists from one list."""
    for i in range(0, len(l), n):
        yield l[i:i + n]
