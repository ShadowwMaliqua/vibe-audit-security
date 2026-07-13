# Intentionally vulnerable fixture used to test vibe-audit's own scanners.
import requests
from flask import Flask, request

app = Flask(__name__)
DEBUG = True

def fetch_upstream(url):
    # TLS certificate verification disabled.
    return requests.get(url, verify=False)

def get_user(user_id):
    # SQL built with an f-string instead of a parameterized query.
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

if __name__ == "__main__":
    app.run(debug=True)
