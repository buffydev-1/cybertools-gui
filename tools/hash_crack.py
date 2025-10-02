import hashlib

def crack_hash(target_hash, dict_path, algo='md5', stop_on_first=True):
    algo = algo.lower()
    try:
        hfunc = getattr(hashlib, algo)
    except Exception:
        raise ValueError('Unsupported algorithm')

    found = []
    try:
        with open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                pw = line.rstrip('\n')
                candidate = pw.encode('utf-8')
                he = hfunc(candidate).hexdigest()
                if he == target_hash:
                    found.append(pw)
                    if stop_on_first:
                        return found
    except FileNotFoundError:
        raise
    return found
