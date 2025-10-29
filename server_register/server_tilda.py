# server_tilda.py
import os
import threading
from pathlib import Path
from dotenv import load_dotenv
import logging
from datetime import date
import secrets
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.middleware.proxy_fix import ProxyFix
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# === Загрузка переменных окружения ===
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

# Настройка логирования
logging.basicConfig(
    filename='server_tilda.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# Инициализация Flask
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# === Rate Limiter ===
limiter = Limiter(
    app=app,
    key_func=get_remote_address,  # лимит по IP
    default_limits=[]  # не применяем лимит ко всем роутам
)

# Или кастомная ошибка:
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Слишком много запросов. Попробуйте позже."}), 429

# === Настройки Flask-Mail ===
app.config['MAIL_SERVER'] = 'cubinez.ru'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'postfix@cubinez.ru'
app.config['MAIL_PASSWORD'] = os.getenv('POSTFIX_MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'postfix@cubinez.ru'

mail = Mail(app)

# === CORS — исправлено: убраны пробелы в origins ===
CORS(app, origins=[
    "https://project15827036.tilda.ws",
    "https://test-register-tilda.cubinez.ru.tilda.ws",
    "https://test-register-tilda.cubinez.ru"
])

# === Функции работы с PostgreSQL ===
def get_db_connection():
    return psycopg2.connect(
        host=os.getenv('POSTGRES_HOST', 'localhost'),
        port=os.getenv('POSTGRES_PORT', '5432'),
        dbname=os.getenv('POSTGRES_DB'),
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD'),
        cursor_factory=RealDictCursor
    )

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            fullname TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT,
            password_hash BYTEA NOT NULL,
            birthdate DATE NOT NULL,
            gender TEXT,
            consent BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

def init_reset_tokens_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

def calculate_age(birthdate_str):
    try:
        birthdate = date.fromisoformat(birthdate_str)
        today = date.today()
        age = today.year - birthdate.year
        if (today.month, today.day) < (birthdate.month, birthdate.day):
            age -= 1
        return age
    except ValueError:
        return -1

# === Асинхронная отправка email ===
def send_registration_email_async(email, fullname):
    try:
        with app.app_context():
            msg = Message(
                subject="Регистрация прошла успешно!",
                recipients=[email],
                body=f"Здравствуйте, {fullname}!\n\nВы успешно зарегистрировались на нашем сайте.\nСпасибо за регистрацию!"
            )
            mail.send(msg)
            logging.info(f"Письмо отправлено на {email}")
    except Exception as e:
        logging.warning(f"Не удалось отправить email на {email}: {e}")

def send_password_reset_email_async(email, reset_link):
    try:
        with app.app_context():
            msg = Message(
                subject="Сброс пароля",
                recipients=[email],
                body=f"Здравствуйте!\n\nПерейдите по ссылке, чтобы сбросить пароль:\n{reset_link}\n\nСсылка действует 1 час."
            )
            mail.send(msg)
            logging.info(f"Письмо сброса отправлено на {email}")
    except Exception as e:
        logging.warning(f"Не удалось отправить письмо сброса на {email}: {e}")

@app.after_request
def after_request(response):
    """Логируем информацию о лимитах."""
    if response.status_code == 429:
        logging.warning(f"RATE LIMIT EXCEEDED: {request.remote_addr} - {request.endpoint}")
    return response

# === Инициализация БД при запуске ===
init_db()
init_reset_tokens_table()

# Импорт и регистрация роутов
from routes import register_routes
register_routes(app, get_db_connection, calculate_age, send_registration_email_async, send_password_reset_email_async, limiter)

# === Запуск сервера ===
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
