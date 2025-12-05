import hashlib
import itertools
import base64
import re

# Supported algorithms
HASH_TYPES = {
    32: ["md5"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256", "sha3_256", "blake2s"],
    96: ["sha384"],
    128: ["sha512", "sha3_512", "blake2b"],
}

def detect_hash_type(h):
    """Return all possible hash algorithms matching the hash length."""
    length = len(h)
    return HASH_TYPES.get(length, [])


def apply_hash(algo, text, salt=None):
    """Hash using provided algorithm and optional salt."""
    if salt:
        text = salt + text

    h = getattr(hashlib, algo)
    return h(text.encode()).hexdigest()


def brute_force_crack(target, algos, max_len=4):
    """Bruteforce lowercase a-z for short lengths."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"

    for l in range(1, max_len + 1):
        for combo in itertools.product(chars, repeat=l):
            word = "".join(combo)
            for algo in algos:
                if apply_hash(algo, word) == target:
                    return f"[+] Cracked by brute force: {word}"
    return None


def mutation_rules(word):
    """Generate variations like p@ssword / PAssword / password123."""
    variations = set()
    variations.add(word)
    variations.add(word.lower())
    variations.add(word.upper())
    variations.add(word.capitalize())
    variations.add(word + "123")
    variations.add("123" + word)

    # Leet conversions
    leet = word.replace("a", "4").replace("e", "3").replace("o", "0").replace("i", "1")
    variations.add(leet)

    return variations


def crack_hash(target_hash, wordlist_path="wordlist.txt"):
    print(f"[*] Hash Provided: {target_hash}")

    possible_algos = detect_hash_type(target_hash)

    if not possible_algos:
        print("[!] Unknown hash format. Cannot identify algorithm.")
        return

    print(f"[+] Possible Algorithms: {', '.join(possible_algos)}")

    # Wordlist cracking
    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            for word in f:
                word = word.strip()

                # Mutate word into many forms
                for variant in mutation_rules(word):
                    for algo in possible_algos:
                        if apply_hash(algo, variant) == target_hash:
                            print(f"[+] Match Found!")
                            print(f"[+] Algorithm: {algo.upper()}")
                            print(f"[+] Plaintext: {variant}")
                            return
    except FileNotFoundError:
        print("[!] wordlist.txt missing - create it!")
        return

    print("[!] Dictionary-based cracking failed.")
    print("[*] Attempting brute-force (short length)...")

    # Brute force small passwords
    brute = brute_force_crack(target_hash, possible_algos)
    if brute:
        print(brute)
        return

    print("[!] Unable to crack hash. It may be too strong.")
