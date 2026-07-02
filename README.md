# Cafe Website

A full-stack Flask application for discovering cafés, viewing café details, making reservations, and managing café listings. The project includes user registration/login, café posting for owners, image uploads, and booking management features.

## English

### Overview
This project is a café discovery and booking web application built with Flask. Users can browse cafés, open detailed café pages, and make reservations after logging in. Registered café owners can add new cafés, attach images, and manage bookings for their own cafés.

### Main Features
- Browse a list of cafés on the home page
- View detailed café information, including images, address, and opening hours
- Register and log in as a user
- Make reservations for a café
- Upload café listings with images
- Manage bookings and approve or cancel reservations
- Store images using AWS S3

### Tech Stack
- Python 3.11
- Flask
- Jinja2 / Bootstrap-based templates
- PostgreSQL via psycopg2
- AWS S3 for image storage
- Vercel deployment configuration

### Project Structure
- app.py: main Flask application and routes
- templates/: HTML pages for home, detail, login, register, upload, booking, and confirmation
- static/: CSS, JavaScript, and image assets
- requirements.txt: Python dependencies
- vercel.json: deployment configuration for Vercel

### Environment Variables
Before running the app, set the following environment variables:
- DATABASE_URL: PostgreSQL connection string
- AWS_ACCESS_KEY_ID: AWS access key
- AWS_SECRET_ACCESS_KEY: AWS secret key
- S3_BUCKET_NAME: AWS S3 bucket name
- AWS_REGION: AWS region (default: ap-northeast-1)

### Installation
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Running Locally
```bash
export DATABASE_URL="your_postgresql_connection_string"
python app.py
```

Then open http://127.0.0.1:8000 in your browser.

### Deployment
This repository includes a Vercel configuration, so it can be deployed as a Python-based web app. Make sure the required environment variables are configured in the deployment platform.

---

## 日本語

### 概要
このプロジェクトは、Flaskで構築されたカフェ探索・予約Webアプリケーションです。ユーザーはカフェを一覧で閲覧し、詳細ページから予約を行うことができます。登録済みのカフェオーナーは、新しいカフェを追加したり、画像を添付したり、予約を管理したりできます。

### 主な機能
- ホームページでカフェ一覧を閲覧できる
- 画像・住所・営業時間などを含むカフェ詳細ページを表示できる
- ユーザー登録・ログインができる
- カフェの予約ができる
- 画像付きでカフェ情報を投稿できる
- 予約を管理し、承認・キャンセルできる
- AWS S3を使って画像を保存できる

### 使用技術
- Python 3.11
- Flask
- Jinja2 / Bootstrapベースのテンプレート
- psycopg2によるPostgreSQL連携
- 画像保存用にAWS S3を利用
- Vercel向けデプロイ設定あり

### プロジェクト構成
- app.py: メインのFlaskアプリケーションとルーティング
- templates/: ログイン・登録・カフェ詳細・アップロード・予約関連のHTMLテンプレート
- static/: CSS、JavaScript、画像ファイル
- requirements.txt: Python依存パッケージ
- vercel.json: Vercelデプロイ用設定

### 環境変数
アプリを実行する前に、次の環境変数を設定してください。
- DATABASE_URL: PostgreSQL接続文字列
- AWS_ACCESS_KEY_ID: AWSアクセスキー
- AWS_SECRET_ACCESS_KEY: AWSシークレットキー
- S3_BUCKET_NAME: AWS S3バケット名
- AWS_REGION: AWSリージョン（省略時は ap-northeast-1）

### ローカル実行手順
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

```bash
export DATABASE_URL="your_postgresql_connection_string"
python app.py
```

その後、ブラウザで http://127.0.0.1:8000 を開いてください。

### デプロイについて
このリポジトリにはVercel用の設定ファイルが含まれているため、Pythonアプリとしてデプロイできます。デプロイ先の環境変数も必ず設定してください。
