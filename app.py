"""
DocumentFlow — система документооборота с электронной подписью.
Основной файл приложения (Flask).
"""

import io
import os
import sys
import secrets
import sqlite3
import zipfile
import binascii
from pathlib import Path
from uuid import uuid4
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

import database as db
import signature as sig

app = Flask(__name__)
# Случайный секрет хранится вне исходного кода и не включается в архив.
secret_path = Path(__file__).with_name(".session_secret")
if os.environ.get("DOCUMENTFLOW_SECRET"):
    app.secret_key = os.environ["DOCUMENTFLOW_SECRET"]
else:
    try:
        fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_hex(32))
    app.secret_key = secret_path.read_text().strip()
    if len(app.secret_key) < 32:
        raise RuntimeError("Некорректный секрет сессий")
app.config.update(MAX_CONTENT_LENGTH=16 * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

UPLOAD_FOLDER = os.environ.get("DOCUMENTFLOW_UPLOADS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads"))
ALLOWED_EXTENSIONS = {"pdf", "docx", "xlsx", "txt", "png", "jpg", "doc"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
db.init_db()


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_forms():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        actual = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected, actual):
            abort(400, description="Форма устарела. Обновите страницу и повторите действие.")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(413)
def too_large(error):
    return render_template("error.html", message="Размер запроса превышает 16 МиБ."), 413


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(409)
def request_error(error):
    return render_template("error.html", message=error.description), error.code


def owned_document(doc_id):
    doc = db.get_document_by_id(doc_id)
    if doc is None:
        abort(404, description="Документ не найден.")
    if doc["author_id"] != session["user_id"]:
        abort(403, description="Нет доступа к этому документу.")
    return doc


def read_document(doc):
    # Не доверяем абсолютному пути из старой базы: файлы ищутся в uploads.
    path = Path(app.config["UPLOAD_FOLDER"]) / Path(doc["filepath"]).name
    try:
        return path.read_bytes()
    except OSError:
        abort(404, description="Файл документа отсутствует или недоступен.")


def as_bytes(value):
    return value.encode("utf-8") if isinstance(value, str) else value


def signed_document(doc_id):
    """Документ владельца, его подпись и данные подписавшего после проверки подписи."""
    doc = owned_document(doc_id)
    sig_info = db.get_signature_for_document(doc_id)
    if not sig_info:
        abort(404, description="Документ не подписан.")
    file_data = read_document(doc)
    signer = db.get_user_by_id(sig_info["user_id"])
    try:
        public_key = sig.load_public_key(as_bytes(signer["public_key_pem"]))
        signature = sig.decode_signature_b64(sig_info["signature_b64"])
        is_valid = sig.verify_signature(file_data, signature, public_key)
    except (ValueError, TypeError, binascii.Error):
        is_valid = False
    if not is_valid:
        abort(409, description="Подпись не соответствует файлу. Скачивание подписи отменено.")
    return doc, sig_info, signer, file_data, signature


def signature_info_text(doc, sig_info, signer, file_data, signature):
    """Текстовое описание подписи для архива с документом."""
    name = doc["filename"]
    cert_pem = as_bytes(signer["certificate_pem"])
    return "\r\n".join([
        "Сведения об электронной подписи (DocumentFlow)",
        "",
        f"Документ: {name}",
        f"SHA-256 документа: {db.compute_checksum(file_data)}",
        f"Подписал: {sig_info['signer_name']}",
        f"Дата подписания (UTC): {sig_info['signed_at']}",
        f"Отпечаток SHA-256 сертификата: {sig.certificate_fingerprint(cert_pem)}",
        "",
        "Алгоритм: RSASSA-PSS (RFC 8017), ключ RSA-2048, хэш-функция SHA-256,",
        "функция генерации маски MGF1 с SHA-256.",
        f"Файл {name}.sig содержит открепленную подпись длиной {len(signature)} байт",
        "без контейнера CMS. Сертификат подписанта самоподписанный и не выдан",
        "аккредитованным удостоверяющим центром.",
        "",
        "Проверка с помощью OpenSSL 3:",
        f'openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto '
        f'-verify public_key.pem -signature "{name}.sig" "{name}"',
        "",
    ]).encode("utf-8-sig")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session or db.get_user_by_id(session["user_id"]) is None:
            flash("Необходимо войти в систему.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---- Аутентификация ----

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not 1 <= len(username) <= 64 or len(username.encode("utf-8")) > 64 or not 8 <= len(password) <= 128:
            flash("Логин: 1–64 байта; пароль: 8–128 символов.", "danger")
            return redirect(url_for("register"))

        if db.get_user_by_username(username):
            flash("Пользователь с таким именем уже существует.", "danger")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        # Генерация ключевой пары и сертификата
        private_key = sig.generate_key_pair()
        private_pem = sig.serialize_private_key(private_key, password.encode("utf-8"))
        public_pem = sig.serialize_public_key(private_key)
        cert = sig.generate_certificate(private_key, username)
        cert_pem = sig.serialize_certificate(cert)

        try:
            user_id = db.create_user(username, password_hash, private_pem, public_pem, cert_pem)
        except sqlite3.IntegrityError:
            flash("Пользователь с таким именем уже существует.", "danger")
            return redirect(url_for("register"))
        session.clear()

        session["user_id"] = user_id
        session["username"] = username
        flash(f"Регистрация успешна. Ключевая пара RSA-2048 и сертификат X.509 сгенерированы.", "success")
        return redirect(url_for("documents_list"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.get_user_by_username(username)
        if user and len(password) <= 128 and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Вход выполнен.", "success")
            return redirect(url_for("documents_list"))
        else:
            flash("Неверное имя пользователя или пароль.", "danger")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("login"))


# ---- Документы ----

@app.route("/")
@login_required
def documents_list():
    docs = db.get_all_documents(session["user_id"])
    documents = []
    for doc in docs:
        sig_info = db.get_signature_for_document(doc["id"])
        documents.append({
            "id": doc["id"],
            "filename": doc["filename"],
            "upload_date": doc["upload_date"],
            "author_name": doc["author_name"],
            "checksum": doc["checksum"][:16] + "...",
            "is_signed": sig_info is not None,
            "signer_name": sig_info["signer_name"] if sig_info else None,
            "signed_at": sig_info["signed_at"] if sig_info else None,
        })
    return render_template("documents.html", documents=documents, username=session["username"])


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_document():
    if request.method == "POST":
        if "document" not in request.files:
            flash("Файл не выбран.", "danger")
            return redirect(url_for("upload_document"))

        file = request.files["document"]
        if file.filename == "":
            flash("Файл не выбран.", "danger")
            return redirect(url_for("upload_document"))

        if file and allowed_file(file.filename):
            filename = file.filename.replace("\\", "/").rsplit("/", 1)[-1]
            if len(filename) > 200 or any(ord(c) < 32 for c in filename):
                abort(400, description="Недопустимое имя файла.")
            stored_name = uuid4().hex + "." + filename.rsplit(".", 1)[1].lower()
            file_data = file.read()
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
            with open(filepath, "xb") as f:
                f.write(file_data)
            checksum = db.compute_checksum(file_data)
            try:
                db.insert_document(filename, stored_name, session["user_id"], checksum)
            except sqlite3.Error:
                os.remove(filepath)
                raise
            flash(f"Документ «{filename}» загружен. SHA-256: {checksum[:32]}...", "success")
            return redirect(url_for("documents_list"))
        else:
            flash(f"Недопустимый формат файла. Разрешены: {', '.join(sorted(ALLOWED_EXTENSIONS))}", "danger")

    return render_template("upload.html", username=session["username"])


@app.route("/download/<int:doc_id>")
@login_required
def download_document(doc_id):
    doc = owned_document(doc_id)
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        Path(doc["filepath"]).name,
        as_attachment=True, download_name=doc["filename"]
    )


@app.route("/download/<int:doc_id>/signature")
@login_required
def download_signature(doc_id):
    doc, _, _, _, signature = signed_document(doc_id)
    return send_file(io.BytesIO(signature), mimetype="application/octet-stream",
                     as_attachment=True, download_name=doc["filename"] + ".sig")


@app.route("/download/<int:doc_id>/package")
@login_required
def download_package(doc_id):
    doc, sig_info, signer, file_data, signature = signed_document(doc_id)
    name = doc["filename"]
    # Имя файла сведений не должно совпасть с именем самого документа.
    info_name = "signature_info.txt" if name != "signature_info.txt" else "signature_info_1.txt"
    info = signature_info_text(doc, sig_info, signer, file_data, signature)
    cert_pem = as_bytes(signer["certificate_pem"])
    public_pem = as_bytes(signer["public_key_pem"])
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, file_data)
        archive.writestr(name + ".sig", signature)
        archive.writestr("certificate.pem", cert_pem)
        archive.writestr("public_key.pem", public_pem)
        archive.writestr(info_name, info)
    buffer.seek(0)
    return send_file(buffer, mimetype="application/zip", as_attachment=True,
                     download_name=name.rsplit(".", 1)[0] + "_signed.zip")


# ---- Подписание и верификация ----

@app.route("/sign/<int:doc_id>", methods=["POST"])
@login_required
def sign_doc(doc_id):
    doc = owned_document(doc_id)

    # Проверка наличия подписи
    existing_sig = db.get_signature_for_document(doc_id)
    if existing_sig:
        flash("Документ уже подписан.", "warning")
        return redirect(url_for("documents_list"))

    # Чтение файла
    file_data = read_document(doc)

    # Загрузка закрытого ключа пользователя
    user = db.get_user_by_id(session["user_id"])
    password = request.form.get("password", "")
    if len(password) > 128 or not check_password_hash(user["password_hash"], password):
        abort(403, description="Неверный пароль для подписания.")
    if db.compute_checksum(file_data) != doc["checksum"]:
        abort(409, description="Файл изменён после загрузки. Загрузите новую версию.")
    try:
        private_key = sig.load_private_key(user["private_key_pem"], password.encode("utf-8"))
    except (ValueError, TypeError):
        abort(409, description="Не удалось открыть закрытый ключ. Используйте учётную запись новой версии.")

    # Формирование подписи
    signature = sig.sign_document(file_data, private_key)
    sig_b64 = sig.encode_signature_b64(signature)

    # Сохранение подписи
    try:
        db.save_signature(doc_id, session["user_id"], sig_b64)
    except sqlite3.IntegrityError:
        abort(409, description="Документ уже подписан.")
    flash(f"Документ «{doc['filename']}» успешно подписан (RSA-PSS, SHA-256).", "success")
    return redirect(url_for("documents_list"))


@app.route("/verify/<int:doc_id>")
@login_required
def verify_doc(doc_id):
    doc = owned_document(doc_id)

    sig_info = db.get_signature_for_document(doc_id)
    if not sig_info:
        flash("Документ не подписан.", "warning")
        return redirect(url_for("documents_list"))

    # Чтение файла
    file_data = read_document(doc)

    # Загрузка открытого ключа подписавшего
    signer = db.get_user_by_id(sig_info["user_id"])
    try:
        public_key = sig.load_public_key(signer["public_key_pem"])
        signature = sig.decode_signature_b64(sig_info["signature_b64"])
        is_valid = sig.verify_signature(file_data, signature, public_key)
    except (ValueError, TypeError, binascii.Error):
        is_valid = False

    # Текущая контрольная сумма
    current_checksum = db.compute_checksum(file_data)
    checksum_match = current_checksum == doc["checksum"]

    return render_template("verify.html",
                           doc=doc,
                           sig_info=sig_info,
                           is_valid=is_valid,
                           checksum_match=checksum_match,
                           current_checksum=current_checksum,
                           original_checksum=doc["checksum"],
                           username=session["username"])


@app.route("/keys")
@login_required
def my_keys():
    user = db.get_user_by_id(session["user_id"])
    public_key_pem = user["public_key_pem"].decode("utf-8") if isinstance(user["public_key_pem"], bytes) else user["public_key_pem"]
    cert_pem = user["certificate_pem"].decode("utf-8") if isinstance(user["certificate_pem"], bytes) else user["certificate_pem"]
    return render_template("keys.html",
                           public_key=public_key_pem,
                           certificate=cert_pem,
                           username=session["username"])


if __name__ == "__main__":
    db.init_db()
    print("DocumentFlow запущен: http://127.0.0.1:5000")
    app.run(debug=False, host="127.0.0.1", port=5000)
