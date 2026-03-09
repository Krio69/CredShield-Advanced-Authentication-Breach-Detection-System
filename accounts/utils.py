import hashlib
import requests

def check_password_breach(password):
    """
    Checks if a password has been leaked using k-Anonymity.
    Returns the count of leaks or 0 if safe.
    """
    # 1. Hash the password using SHA-1
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    # 2. Query the Pwned Passwords API (Anonymized)
    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            return 0

        # 3. Search for our suffix in the results
        # The API returns a list of SUFFIX:COUNT
        hashes = (line.split(':') for line in response.text.splitlines())
        for h_suffix, count in hashes:
            if h_suffix == suffix:
                return int(count)
    except Exception:
        return 0 # Fail silently if API is down
        
    return 0