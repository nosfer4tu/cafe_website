from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import base64
import hashlib
import secrets

app = Flask(__name__)

RESTORE_FOLDER = "static/img"
HASH_ALGORITHM = "pbkdf2_sha256"
app.secret_key = b"opensesame"

def convert_data(file_name):
    with open(file_name, "rb") as f:
        binary_data = f.read()
    return binary_data
def get_db():
    db = sqlite3.connect("todo.db")
    db.row_factory = sqlite3.Row
    return db

def get_cafe_by_id(cafe_id):
    db = get_db()
    cursor = db.cursor()
    cafe = cursor.execute('SELECT * FROM cafes WHERE id = ?', (cafe_id,)).fetchone()
    cursor.close()
    return cafe

def get_images_for_cafe(cafe_id):
    db = get_db()
    cursor = db.cursor()
    images = cursor.execute('SELECT * FROM images WHERE cafe_id = ?', (cafe_id,)).fetchall()
    cursor.close()
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

    db = get_db()
    try:
        with db:
            row = db.execute(
                "SELECT * FROM users where username = ?", (username,)
            ).fetchone()

            verified = row is not None and verify_password(
                password, row["password_hash"]
            )

            if verified:
                session["user_id"] = row["id"]
                return redirect(url_for("index"))
            else:
                return render_template("login.html", error_login=True)
    finally:
        db.close()

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

    db = get_db()
    try:
        with db:
            res = db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchall()
            if len(res) != 0:
                return render_template(
                    "register.html", error_unique=True, form=request.form
                )

            password_hash = hash_password(password)
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )

        return redirect(url_for("login_form"))
    finally:
        db.close()

@app.route("/", methods=["GET"])
def index():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM cafes")
    records = cursor.fetchall()

    cursor.execute("SELECT id, image1, image2, image3, image4, image5 FROM cafes")
    rows = cursor.fetchall()
    cursor.close()

    images_by_cafe = {}

    for row in rows:
        cafe_id = row[0]
        image1 = f"data:image/png;base64,{base64.b64encode(row[1]).decode('utf-8')}" if row[1] else None
        image2 = f"data:image/png;base64,{base64.b64encode(row[2]).decode('utf-8')}" if row[2] else None
        image3 = f"data:image/png;base64,{base64.b64encode(row[3]).decode('utf-8')}" if row[3] else None
        image4 = f"data:image/png;base64,{base64.b64encode(row[4]).decode('utf-8')}" if row[4] else None
        image5 = f"data:image/png;base64,{base64.b64encode(row[5]).decode('utf-8')}" if row[5] else None

        images_by_cafe[cafe_id] = {
            "image1": image1,
            "image2": image2,
            "image3": image3,
            "image4": image4,
            "image5": image5,
        }

    return render_template("index.html", records=records, images_by_cafe=images_by_cafe)


@app.route("/d/<int:cafes_id>", methods=["GET"])
def d(cafes_id):
    db = get_db()
    
    cursor = db.cursor()
    cursor.execute("SELECT * FROM cafes WHERE id = ?", (cafes_id,))
    cafe = cursor.fetchone()

    if cafe is None:
        return "Cafe not found", 404
    
    images = [{
        "image1": f"data:image/png;base64,{base64.b64encode(cafe['image1']).decode('utf-8')}" if cafe['image1'] else None,
        "image2": f"data:image/png;base64,{base64.b64encode(cafe['image2']).decode('utf-8')}" if cafe['image2'] else None,
        "image3": f"data:image/png;base64,{base64.b64encode(cafe['image3']).decode('utf-8')}" if cafe['image3'] else None,
        "image4": f"data:image/png;base64,{base64.b64encode(cafe['image4']).decode('utf-8')}" if cafe['image4'] else None,
        "image5": f"data:image/png;base64,{base64.b64encode(cafe['image5']).decode('utf-8')}" if cafe['image5'] else None,
    }]
    
    return render_template("detail.html", record=cafe, images=images)



@app.route("/upload", methods = ["GET"])
def upload_get():
    return render_template("upload.html")
@app.route("/upload", methods = ["POST"])
def upload():
    if request.method == "POST":
        cafe_name = request.form["cafe_name"]
        zipcode = request.form["postal_code"]
        prefecture = request.form["prefectures"]
        municipality = request.form["municipalities"]
        opening_hours = request.form["opening_hours"]
        description = request.form["cafe_details"]
        files = request.files.getlist('images[]')
        
        for file in files:
            if file and file.name:
                image1 = files[0].read()
                image2 = files[1].read()
                image3 = files[2].read()
                image4 = files[3].read()
                image5 = files[4].read()
                db = get_db()
                try:
                    with db:
                        db.execute(
                            """
                            INSERT INTO cafes (cafe_name, zipcode, prefecture, municipality, opening_hours, description, image1, image2, image3, image4, image5)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (cafe_name, zipcode, prefecture, municipality, opening_hours, description, image1, image2, image3, image4, image5),
                        )
                        return redirect(url_for("index"))
                finally:
                    db.close()    

@app.route("/b/<int:user_id>", methods=["GET"])
def b(user_id):
    query_bookings = f"""
        SELECT bookings.user_id, users.username, cafes.cafe_name, bookings.date, bookings.time, bookings.num_people, bookings.user_id, bookings.cafe_id
        FROM bookings
        INNER JOIN cafes ON cafes.id = bookings.cafe_id
        INNER JOIN users ON users.id = bookings.user_id
        WHERE bookings.user_id = {user_id}
    """
    query_users = "SELECT id, username FROM users"
    query_cafes = """
        SELECT id, cafe_name, zipcode, prefecture, municipality, opening_hours, description
        FROM cafes
    """

    db = get_db()
    with db:
        cursor = db.cursor()
        cursor.execute(query_bookings)
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
        VALUES (?, ?, ?, ?, ?, ?)
    """

    db = get_db()
    with db:
        cursor = db.cursor()
        cursor.execute(insert_query, (
            session["user_id"],
            request.form["cafe_id"],
            request.form["name"],
            request.form["date"],
            request.form["time"],
            request.form["num_people"],
        ))
    return redirect(url_for("confirmation"))

@app.route("/confirmation", methods=["GET"])
def confirmation():
    return render_template("confirmation.html")
    

if __name__ == "__main__":
    app.run(port=8000, debug=True)    

