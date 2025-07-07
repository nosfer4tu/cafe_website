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
from werkzeug.utils import secure_filename
import uuid
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

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
    print("Form keys:", list(request.form.keys()), flush=True)
    print("image_urls raw:", request.form.get("image_urls"), flush=True)
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

def upload_to_s3(file):
    """
    Upload a file to AWS S3 and return the public URL
    """
    try:
        # Get AWS credentials from environment
        aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        region = os.environ.get('AWS_REGION', 'ap-northeast-1')
        
        if not all([aws_access_key, aws_secret_key, bucket_name]):
            raise ValueError("AWS credentials not properly configured. Please set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and S3_BUCKET_NAME environment variables.")
        
        # Create S3 client
        s3 = boto3.client(
            's3',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        # Generate unique filename
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        
        # Upload file
        file.seek(0)  # Reset file pointer
        s3.upload_fileobj(
            file, 
            bucket_name, 
            unique_filename,
            ExtraArgs={
                'ContentType': file.content_type
            }
        )
        
        # Return public URL
        file_url = f"https://{bucket_name}.s3.{region}.amazonaws.com/{unique_filename}"
        return file_url
        
    except NoCredentialsError:
        raise Exception("AWS credentials not found. Please check your environment variables.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucket':
            raise Exception(f"S3 bucket '{bucket_name}' does not exist.")
        elif error_code == 'AccessDenied':
            raise Exception("Access denied to S3 bucket. Check your AWS permissions.")
        else:
            raise Exception(f"AWS S3 error: {e}")
    except Exception as e:
        logging.error(f"Error uploading to S3: {e}")
        raise

def save_url_to_neon(file_url, cafe_id=None):
    """
    Save file URL to Neon database
    """
    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                if cafe_id:
                    # Update existing cafe with image URL
                    cursor.execute(
                        "UPDATE cafes SET image1 = %s WHERE id = %s",
                        (file_url, cafe_id)
                    )
                else:
                    # For testing purposes, you could create a separate images table
                    cursor.execute(
                        "INSERT INTO image_urls (url, created_at) VALUES (%s, NOW())",
                        (file_url,)
                    )
            conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error saving URL to database: {e}")
        return False

@app.route('/upload_file', methods=['POST'])
def upload_file():
    """
    Simple file upload endpoint for testing
    """
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Check AWS credentials before attempting upload
        aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        region = os.environ.get('AWS_REGION', 'us-east-1')
        
        # Log environment variables for debugging (remove in production)
        logging.info(f"AWS_ACCESS_KEY_ID: {'SET' if aws_access_key else 'NOT SET'}")
        logging.info(f"AWS_SECRET_ACCESS_KEY: {'SET' if aws_secret_key else 'NOT SET'}")
        logging.info(f"S3_BUCKET_NAME: {bucket_name}")
        logging.info(f"AWS_REGION: {region}")
        
        if not aws_access_key:
            return jsonify({"error": "AWS_ACCESS_KEY_ID not configured"}), 500
        if not aws_secret_key:
            return jsonify({"error": "AWS_SECRET_ACCESS_KEY not configured"}), 500
        if not bucket_name:
            return jsonify({"error": "S3_BUCKET_NAME not configured"}), 500
        
        # Upload to S3
        file_url = upload_to_s3(file)
        
        # Save URL to database
        save_url_to_neon(file_url)
        
        return jsonify({"url": file_url, "success": True})
        
    except Exception as e:
        logging.error(f"Upload error: {e}")
        # Ensure we always return JSON, even on errors
        return jsonify({"error": str(e)}), 500

@app.route('/upload_file_server', methods=['POST'])
def upload_file_server():
    """
    Server-side upload endpoint (fallback for CORS issues)
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Upload to S3 through server
        file_url = upload_to_s3(file)
        
        return jsonify({"url": file_url, "success": True})
        
    except Exception as e:
        logging.error(f"Server upload error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/debug-env')
def debug_env():
    """Temporary route to check environment variables"""
    return jsonify({
        "aws_access_key": "SET" if os.environ.get('AWS_ACCESS_KEY_ID') else "NOT SET",
        "aws_secret_key": "SET" if os.environ.get('AWS_SECRET_ACCESS_KEY') else "NOT SET", 
        "bucket_name": os.environ.get('S3_BUCKET_NAME', "NOT SET"),
        "region": os.environ.get('AWS_REGION', "NOT SET"),
        "all_env_vars": {k: v for k, v in os.environ.items() if 'AWS' in k or 'S3' in k}
    })

@app.route('/test-json')
def test_json():
    """Simple test endpoint to verify JSON responses work"""
    return jsonify({"message": "JSON response working", "status": "success"})

@app.route('/get-presigned-url', methods=['POST'])
def get_presigned_url():
    """Get a presigned URL for direct S3 upload"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        content_type = data.get('contentType', 'image/jpeg')
        
        if not filename:
            return jsonify({"error": "Filename required"}), 400
        
        # Check AWS credentials
        aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        region = os.environ.get('AWS_REGION', 'us-east-1')
        
        if not all([aws_access_key, aws_secret_key, bucket_name]):
            return jsonify({"error": "AWS credentials not configured"}), 500
        
        # Create S3 client
        s3 = boto3.client(
            's3',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        # Generate unique filename
        unique_filename = f"{uuid.uuid4()}_{secure_filename(filename)}"
        
        # Generate presigned URL with CORS headers
        presigned_url = s3.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': bucket_name,
                'Key': unique_filename,
                'ContentType': content_type
            },
            ExpiresIn=3600
        )
        
        # Return the presigned URL and the final public URL
        public_url = f"https://{bucket_name}.s3.{region}.amazonaws.com/{unique_filename}"
        
        return jsonify({
            "presignedUrl": presigned_url,
            "publicUrl": public_url,
            "filename": unique_filename
        })
        
    except Exception as e:
        logging.error(f"Error generating presigned URL: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/test-upload-simple', methods=['POST'])
def test_upload_simple():
    """Minimal upload test without S3"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file"}), 400
        
        file = request.files['file']
        return jsonify({
            "filename": file.filename,
            "content_type": file.content_type,
            "file_size": len(file.read()),
            "env_check": {
                "aws_key": "SET" if os.environ.get('AWS_ACCESS_KEY_ID') else "NOT SET",
                "bucket": os.environ.get('S3_BUCKET_NAME', "NOT SET")
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=8000, debug=True)
