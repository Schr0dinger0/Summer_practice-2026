import hmac, hashlib, sys

# Секрет скрыт от условия задачи.
SECRET = b"correct-horse-battery"

def expected(nonce: str, data: str) -> str:
    return hmac.new(SECRET, f"{nonce}|{data}".encode(), hashlib.sha256).hexdigest()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: verify.py <nonce> <data> <response>")
        sys.exit(2)
    nonce, data, resp = sys.argv[1], sys.argv[2], sys.argv[3]
    print("OK" if hmac.compare_digest(expected(nonce, data), resp) else "FAIL")