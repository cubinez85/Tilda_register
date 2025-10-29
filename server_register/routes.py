# routes.py
from flask import request, jsonify
import bcrypt
from email_validator import validate_email, EmailNotValidError
import secrets
from datetime import datetime, timedelta
import logging
import threading
import psycopg2


def get_email_or_ip():
    """Безопасно извлекает email из JSON или возвращает IP."""
    try:
        data = request.get_json()
        if data and isinstance(data, dict):
            email = data.get('email')
            if email and isinstance(email, str) and '@' in email:
                return email.strip().lower()
    except Exception:
        pass
    return get_remote_address()


def register_routes(app, get_db_connection, calculate_age, send_registration_email_async, send_password_reset_email_async, limiter):

    @app.route('/')
    def hello():
        return "Tilda Registration Server is running."

    @app.route('/api/login', methods=['POST'])
    @limiter.limit("5 per minute", key_func=get_email_or_ip)
    def login():
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Тело запроса должно быть в формате JSON"}), 400

            email = data.get('email', '').strip()
            password = data.get('password', '')

            if not email or not password:
                return jsonify({"error": "Email и пароль обязательны"}), 400

            try:
                valid = validate_email(email)
                email = valid.email
            except EmailNotValidError:
                return jsonify({"error": "Некорректный email"}), 400

            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute('SELECT id, email, password_hash FROM users WHERE email = %s', (email,))
                user = cur.fetchone()
                if not user:
                    return jsonify({"error": "Неверный email или пароль"}), 401

                # Преобразуем memoryview → bytes (PostgreSQL BYTEA)
                stored_hash = bytes(user['password_hash'])

                if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    return jsonify({"error": "Неверный email или пароль"}), 401

                return jsonify({"message": "Вход выполнен", "user_id": user['id']}), 200

            finally:
                cur.close()
                conn.close()

        except Exception as e:
            logging.error(f"Ошибка входа: {e}")
            return jsonify({"error": "Внутренняя ошибка сервера"}), 500

    @app.route('/api/register', methods=['POST'])
    @limiter.limit("10 per hour", key_func=get_email_or_ip)
    def register():
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Некорректный JSON"}), 400

            fullname = data.get('fullname', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '')
            password_confirm = data.get('password_confirm', '')
            birthdate_str = data.get('birthdate', '')
            phone = data.get('phone', '').strip() or None
            gender = data.get('gender')
            consent = data.get('consent')

            if not fullname or not email or not password or not password_confirm or not birthdate_str:
                return jsonify({"error": "Все обязательные поля должны быть заполнены"}), 400

            if consent != "on":
                return jsonify({"error": "Требуется согласие на обработку персональных данных"}), 400

            if password != password_confirm:
                return jsonify({"error": "Пароли не совпадают"}), 400

            if len(password) < 6:
                return jsonify({"error": "Пароль должен содержать не менее 6 символов"}), 400

            try:
                valid = validate_email(email)
                email = valid.email
            except EmailNotValidError:
                return jsonify({"error": "Некорректный адрес электронной почты"}), 400

            age = calculate_age(birthdate_str)
            if age < 13:
                return jsonify({"error": "Регистрация разрешена только с 13 лет"}), 400

            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute('''
                    INSERT INTO users (fullname, email, phone, password_hash, birthdate, gender, consent)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', (fullname, email, phone, password_hash, birthdate_str, gender, True))
                conn.commit()
            except psycopg2.IntegrityError as e:
                if 'users_email_key' in str(e) or 'unique constraint' in str(e).lower():
                    return jsonify({"error": "Пользователь с таким email уже существует"}), 409
                else:
                    raise e
            finally:
                cur.close()
                conn.close()

            threading.Thread(
                target=send_registration_email_async,
                args=(email, fullname),
                daemon=True
            ).start()

            logging.info(f"Новый пользователь зарегистрирован: {email}")
            return jsonify({"message": "Регистрация прошла успешно!"}), 201

        except Exception as e:
            logging.error(f"Ошибка регистрации: {str(e)}")
            return jsonify({"error": "Внутренняя ошибка сервера"}), 500

    @app.route('/api/forgot-password', methods=['POST'])
    @limiter.limit("3 per hour", key_func=get_email_or_ip)
    def forgot_password():
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Тело запроса должно быть в формате JSON"}), 400

            email = data.get('email', '').strip()

            if not email:
                return jsonify({"error": "Email обязателен"}), 400

            try:
                valid = validate_email(email)
                email = valid.email
            except EmailNotValidError:
                return jsonify({"error": "Некорректный email"}), 400

            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute('SELECT email FROM users WHERE email = %s', (email,))
                user = cur.fetchone()
                if not user:
                    # Безопасный ответ — не раскрываем существование email
                    return jsonify({"message": "Если email зарегистрирован, вы получите письмо."}), 200

                token = secrets.token_urlsafe(32)
                expires_at = datetime.utcnow() + timedelta(hours=1)

                cur.execute('''
                    INSERT INTO password_reset_tokens (email, token, expires_at)
                    VALUES (%s, %s, %s)
                ''', (email, token, expires_at))
                conn.commit()

                reset_link = f"https://project15827036.tilda.ws/reset-password?token={token}"

                threading.Thread(
                    target=send_password_reset_email_async,
                    args=(email, reset_link),
                    daemon=True
                ).start()

                logging.info(f"Запрос сброса пароля для: {email}")
                return jsonify({"message": "Если email зарегистрирован, вы получите письмо."}), 200

            finally:
                cur.close()
                conn.close()

        except Exception as e:
            logging.error(f"Ошибка forgot-password: {e}")
            return jsonify({"error": "Внутренняя ошибка сервера"}), 500

    @app.route('/api/reset-password', methods=['POST'])
    @limiter.limit("10 per hour", key_func=lambda: request.remote_addr)  # защита от спама
    def reset_password():
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Тело запроса должно быть в формате JSON"}), 400

            token = data.get('token')
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')

            if not token or not new_password or not confirm_password:
                return jsonify({"error": "Все поля обязательны"}), 400

            if new_password != confirm_password:
                return jsonify({"error": "Пароли не совпадают"}), 400

            if len(new_password) < 6:
                return jsonify({"error": "Пароль должен быть не менее 6 символов"}), 400

            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute('''
                    SELECT email, expires_at FROM password_reset_tokens
                    WHERE token = %s
                ''', (token,))
                row = cur.fetchone()

                if not row:
                    return jsonify({"error": "Неверный или устаревший токен"}), 400

                # Убираем timezone info для сравнения
                expires_at = row['expires_at'].replace(tzinfo=None)
                if datetime.utcnow() > expires_at:
                    cur.execute('DELETE FROM password_reset_tokens WHERE token = %s', (token,))
                    conn.commit()
                    return jsonify({"error": "Срок действия токена истёк"}), 400

                email = row['email']
                new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

                cur.execute('UPDATE users SET password_hash = %s WHERE email = %s', (new_hash, email))
                cur.execute('DELETE FROM password_reset_tokens WHERE token = %s', (token,))
                conn.commit()

                logging.info(f"Пароль успешно изменён для: {email}")
                return jsonify({"message": "Пароль успешно обновлён"}), 200

            finally:
                cur.close()
                conn.close()

        except Exception as e:
            logging.error(f"Ошибка reset-password: {e}")
            return jsonify({"error": "Внутренняя ошибка сервера"}), 500
