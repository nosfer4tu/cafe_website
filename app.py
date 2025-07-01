from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import base64
import hashlib
import secrets
import psycopg2
from psycopg2.extras import RealDictCursor  # To get dict-like cursor (similar to sqlite3.Row)
from dotenv import load_dotenv
import os
import logging
import json
import requests

app = Flask(__name__)

RESTORE_FOLDER = "static/img"
HASH_ALGORITHM = "pbkdf2_sha256"
app.secret_key = b"opensesame"

logging.basicConfig(level=logging.INFO)
load_dotenv()

def convert_data(file_name):
    with open(file_name, "rb") as f:
        binary_data = f.read()
    return binary_data

def get_db():
    
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL not set", flush=True)
        raise ValueError("DATABASE_URL environment variable is not set")
    try:
        conn = psycopg2.connect(database_url, sslmode="require")
    except Exception as e:
        print("Database connection error:", e, flush=True)
        raise
    return conn


def get_cafe_by_id(cafe_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute('SELECT * FROM cafes WHERE id = %s', (cafe_id,))
            cafe = cursor.fetchone()
    return cafe

def get_images_for_cafe(cafe_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute('SELECT * FROM images WHERE cafe_id = %s', (cafe_id,))
            images = cursor.fetchall()
    return images

def hash_password(password, salt=None, iterations=310000):
    if salt is None:
        salt = secrets.token_hex(16)
    assert salt and isinstance(salt, str) and "$" not in salt
    assert isinstance(password, str)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
    return "{}${}${}${}".format(HASH_ALGORITHM, iterations, salt, b64_hash)

def verify_password(password, password_hash):
    if (password_hash or "").count("$") != 3:
        return False
    algorithm, iterations, salt, _ = password_hash.split("$", 3)
    iterations = int(iterations)
    assert algorithm == HASH_ALGORITHM
    compare_hash = hash_password(password, salt, iterations)
    return secrets.compare_digest(password_hash, compare_hash)

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("index"))

@app.route("/login", methods=["GET"])
def login_form():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    if not username:
        return render_template("login.html", error_user=True, form=request.form)

    password = request.form.get("password")
    if not password:
        return render_template("login.html", error_password=True, form=request.form)

    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE username = %s", (username,)
            )
            row = cursor.fetchone()

            verified = row is not None and verify_password(
                password, row["password_hash"]
            )

            if verified:
                session["user_id"] = row["id"]
                return redirect(url_for("index"))
            else:
                return render_template("login.html", error_login=True)

@app.route("/register", methods=["GET"])
def register_form():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    if not username or len(username) < 3:
        return render_template("register.html", error_user=True, form=request.form)

    password = request.form.get("password")
    if not password:
        return render_template("register.html", error_password=True, form=request.form)

    password_confirmation = request.form.get("password_confirmation")
    if password != password_confirmation:
        return render_template("register.html", error_confirm=True, form=request.form)

    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE username = %s", (username,)
            )
            res = cursor.fetchall()
            if len(res) != 0:
                return render_template(
                    "register.html", error_unique=True, form=request.form
                )

            password_hash = hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, password_hash),
            )
        conn.commit()

    return redirect(url_for("login_form"))

@app.route("/", methods=["GET"])
def index():
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM cafes ORDER BY id")
            records = cursor.fetchall()

    # No base64 encoding needed; image fields are URLs
    return render_template("index.html", records=records)


@app.route("/d/<int:cafes_id>", methods=["GET"])
def d(cafes_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM cafes WHERE id = %s", (cafes_id,))
            cafe = cursor.fetchone()

    if cafe is None:
        return "Cafe not found", 404

    images = [{
        "image1": cafe['image1'] if cafe['image1'] else None,
        "image2": cafe['image2'] if cafe['image2'] else None,
        "image3": cafe['image3'] if cafe['image3'] else None,
        "image4": cafe['image4'] if cafe['image4'] else None,
        "image5": cafe['image5'] if cafe['image5'] else None,
    }]

    return render_template("detail.html", record=cafe, images=images)


@app.route("/upload", methods=["GET"])
def upload_get():
    return render_template("upload.html")

@app.route("/upload", methods=["POST"])
def upload():
    cafe_name = request.form["cafe_name"]
    zipcode = request.form["postal_code"]
    prefecture = request.form["prefectures"]
    municipality = request.form["municipalities"]
    opening_hours = request.form["opening_hours"]
    description = request.form["cafe_details"]

    # Get image URLs from the form (sent as a JSON string)
    image_urls = json.loads(request.form.get("image_urls", "[]"))

    # Unpack up to 5 image URLs, fill with None if fewer
    image1, image2, image3, image4, image5 = (image_urls + [None]*5)[:5]

    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO cafes (cafe_name, zipcode, prefecture, municipality, opening_hours, description, image1, image2, image3, image4, image5)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        cafe_name,
                        zipcode,
                        prefecture,
                        municipality,
                        opening_hours,
                        description,
                        image1,
                        image2,
                        image3,
                        image4,
                        image5,
                    ),
                )
            conn.commit()
    except Exception as e:
        logging.error(f"Error inserting cafe: {e}")
        return render_template("upload.html", error_insert=True)
    return redirect(url_for("index"))

@app.route("/b/<int:user_id>", methods=["GET"])
def b(user_id):
    query_bookings = """
        SELECT bookings.user_id, users.username, cafes.cafe_name, bookings.date, bookings.time, bookings.num_people, bookings.user_id, bookings.cafe_id
        FROM bookings
        INNER JOIN cafes ON cafes.id = bookings.cafe_id
        INNER JOIN users ON users.id = bookings.user_id
        WHERE bookings.user_id = %s
    """
    query_users = "SELECT id, username FROM users"
    query_cafes = """
        SELECT id, cafe_name, zipcode, prefecture, municipality, opening_hours, description
        FROM cafes
    """

    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query_bookings, (user_id,))
            bookings = cursor.fetchall()
            cursor.execute(query_users)
            users = cursor.fetchall()
            cursor.execute(query_cafes)
            cafes = cursor.fetchall()

    return render_template("booking_description.html", bookings=bookings, users=users, cafes=cafes)

@app.route("/booking", methods=["POST"])
def booking():
    if "user_id" not in session:
        return redirect(url_for("login"))

    insert_query = """
        INSERT INTO bookings (user_id, cafe_id, name, date, time, num_people)
        VALUES (%s, %s, %s, %s, %s, %s)
    """

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(insert_query, (
                session["user_id"],
                request.form["cafe_id"],
                request.form["name"],
                request.form["date"],
                request.form["time"],
                request.form["num_people"],
            ))
        conn.commit()

    return redirect(url_for("confirmation"))

@app.route("/confirmation", methods=["GET"])
def confirmation():
    return render_template("confirmation.html")

@app.route("/api/get-upload-url", methods=["POST"])
def get_upload_url():
    data = request.get_json()
    filename = data.get("filename")
    if not filename:
        return jsonify({"error": "Filename required"}), 400

    # Call Vercel Blob REST API to get an upload URL
    token = os.environ["BLOB_READ_WRITE_TOKEN"]
    api_url = "https://api.vercel.com/v2/blob/upload-url"
    headers = {"Authorization": f"Bearer {token}"}
    res = requests.post(api_url, headers=headers, json={"filename": filename})
    if res.status_code != 200:
        print("Vercel Blob API response:", res.status_code, res.text, flush=True)
        return jsonify({"error": "Failed to get upload URL"}), 500

    data = res.json()
    upload_url = data["url"]
    public_url = data["blob"]["url"]
    return jsonify({"uploadUrl": upload_url, "publicUrl": public_url})

if __name__ == "__main__":
    app.run(port=8000, debug=True)
