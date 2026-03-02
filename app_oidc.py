import base64
import hashlib
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlencode

import httpx
import mysql.connector
from fastapi import Cookie, Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

from dotenv import load_dotenv

load_dotenv()

OIDC_CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
OIDC_CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:8000/callback")

OIDC_AUTHORIZE_URL = "https://phylax.ece140.site/authorize"
OIDC_TOKEN_URL = "https://phylax.ece140.site/token"
OIDC_USERINFO_URL = "https://phylax.ece140.site/userinfo"


class PostCreate(BaseModel):
    title: str
    body: str


def get_db():
    conn = mysql.connector.connect(
        host=os.environ["DB_HOST"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
    )
    try:
        yield conn
    finally:
        conn.close()


def get_current_user(
    session_token: str | None = Cookie(None),
    conn=Depends(get_db),
):
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT users.id, users.username, users.email FROM sessions "
        "JOIN users ON sessions.user_id = users.id "
        "WHERE sessions.session_token = %s",
        (session_token,),
    )
    user = cursor.fetchone()
    cursor.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return user


@asynccontextmanager
async def lifespan(app: FastAPI):
    for _ in range(30):
        try:
            conn = mysql.connector.connect(
                host=os.environ["DB_HOST"],
                user=os.environ["DB_USER"],
                password=os.environ["DB_PASSWORD"],
                database=os.environ["DB_NAME"],
            )
            cursor = conn.cursor()
            with open("init_oidc.sql") as f:
                for statement in f.read().split(";"):
                    statement = statement.strip()
                    if statement:
                        cursor.execute(statement)
            conn.commit()
            cursor.close()
            conn.close()
            break
        except mysql.connector.Error:
            time.sleep(1)
    yield


app = FastAPI(lifespan=lifespan)

# In-memory store for PKCE code verifiers keyed by state
pkce_store: dict[str, str] = {}


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Lab 9 - OIDC</title></head>
    <body>
        <h1>Welcome</h1>
        <a href="/login">Login with OIDC</a>
    </body>
    </html>
    """


@app.get("/login")
def login():
    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    pkce_store[state] = code_verifier

    params = urlencode({
        "response_type": "code",
        "client_id": OIDC_CLIENT_ID,
        "redirect_uri": OIDC_REDIRECT_URI,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    })
    return RedirectResponse(f"{OIDC_AUTHORIZE_URL}?{params}")


@app.get("/callback")
def callback(code: str, state: str, conn=Depends(get_db)):
    code_verifier = pkce_store.pop(state, None)
    if not code_verifier:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    # Exchange authorization code for tokens
    token_response = httpx.post(
        OIDC_TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": OIDC_REDIRECT_URI,
            "client_id": OIDC_CLIENT_ID,
            "client_secret": OIDC_CLIENT_SECRET,
            "code_verifier": code_verifier,
        },
    )
    if token_response.status_code != 200:
        raise HTTPException(status_code=401, detail="Token exchange failed")

    tokens = token_response.json()
    access_token = tokens["access_token"]

    # Fetch user info
    userinfo_response = httpx.get(
        OIDC_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if userinfo_response.status_code != 200:
        raise HTTPException(status_code=401, detail="Failed to fetch user info")

    userinfo = userinfo_response.json()
    sub = userinfo["sub"]
    username = userinfo.get("name", sub)
    email = userinfo.get("email", "")

    # Upsert user: create if new, update if existing
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id FROM users WHERE sub = %s", (sub,))
    existing = cursor.fetchone()
    if existing:
        user_id = existing["id"]
        cursor.execute(
            "UPDATE users SET username = %s, email = %s WHERE id = %s",
            (username, email, user_id),
        )
    else:
        cursor.execute(
            "INSERT INTO users (sub, username, email) VALUES (%s, %s, %s)",
            (sub, username, email),
        )
        user_id = cursor.lastrowid

    # Create session
    session_token = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO sessions (user_id, session_token) VALUES (%s, %s)",
        (user_id, session_token),
    )
    conn.commit()
    cursor.close()

    response = RedirectResponse("/posts")
    response.set_cookie(key="session_token", value=session_token, httponly=True)
    return response


@app.get("/logout")
def logout(session_token: str | None = Cookie(None), conn=Depends(get_db)):
    if session_token:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_token = %s", (session_token,))
        conn.commit()
        cursor.close()
    response = RedirectResponse("/")
    response.delete_cookie("session_token")
    return response


@app.get("/me")
def me(current_user=Depends(get_current_user)):
    return current_user


@app.post("/posts")
def create_post(post: PostCreate, conn=Depends(get_db), current_user=Depends(get_current_user)):
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO posts (user_id, title, body) VALUES (%s, %s, %s)",
        (current_user["id"], post.title, post.body),
    )
    conn.commit()
    post_id = cursor.lastrowid
    cursor.close()
    return {"id": post_id, "user_id": current_user["id"], "title": post.title, "body": post.body}


@app.get("/posts")
def list_posts(conn=Depends(get_db)):
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts")
    posts = cursor.fetchall()
    cursor.close()
    return posts


@app.get("/posts/{post_id}")
def get_post(post_id: int, conn=Depends(get_db)):
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()
    cursor.close()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return post


@app.put("/posts/{post_id}")
def update_post(post_id: int, post: PostCreate, conn=Depends(get_db), current_user=Depends(get_current_user)):
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    existing = cursor.fetchone()
    if not existing:
        cursor.close()
        raise HTTPException(status_code=404, detail="Post not found")
    if existing["user_id"] != current_user["id"]:
        cursor.close()
        raise HTTPException(status_code=403, detail="Not your post")
    cursor.execute(
        "UPDATE posts SET title = %s, body = %s WHERE id = %s",
        (post.title, post.body, post_id),
    )
    conn.commit()
    cursor.close()
    return {"id": post_id, "user_id": current_user["id"], "title": post.title, "body": post.body}


@app.delete("/posts/{post_id}")
def delete_post(post_id: int, conn=Depends(get_db), current_user=Depends(get_current_user)):
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    existing = cursor.fetchone()
    if not existing:
        cursor.close()
        raise HTTPException(status_code=404, detail="Post not found")
    if existing["user_id"] != current_user["id"]:
        cursor.close()
        raise HTTPException(status_code=403, detail="Not your post")
    cursor.execute("DELETE FROM posts WHERE id = %s", (post_id,))
    conn.commit()
    cursor.close()
    return {"detail": "Post deleted"}
