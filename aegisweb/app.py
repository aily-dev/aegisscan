from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    session,
)
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from werkzeug.security import generate_password_hash, check_password_hash

from .models import Base, User
from .scan_runner import run_scan_job


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("AEGIS_WEB_SECRET", "change-this-secret")

    # Database (SQLite file in project root)
    db_path = Path(__file__).resolve().parent.parent / "aegisweb.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    SessionLocal = scoped_session(sessionmaker(bind=engine))

    login_manager = LoginManager(app)
    login_manager.login_view = "login"

    @login_manager.user_loader
    def load_user(user_id: str):
        db = SessionLocal()
        try:
            return db.get(User, int(user_id))
        finally:
            db.close()

    def get_client_ip() -> str:
        return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        SessionLocal.remove()

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        db = SessionLocal()
        try:
            if request.method == "POST":
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "").strip()
                if not username or not password:
                    flash("نام کاربری و رمز عبور الزامی است.", "error")
                    return redirect(url_for("register"))

                existing = db.query(User).filter_by(username=username).first()
                if existing:
                    flash("این نام کاربری قبلاً ثبت شده است.", "error")
                    return redirect(url_for("register"))

                ip = get_client_ip()
                user = User(
                    username=username,
                    password_hash=generate_password_hash(password),
                    registered_ip=ip,
                )
                db.add(user)
                db.commit()
                flash("ثبت‌نام با موفقیت انجام شد. لطفاً وارد شوید.", "success")
                return redirect(url_for("login"))

            return render_template("register.html")
        finally:
            db.close()

    @app.route("/login", methods=["GET", "POST"])
    def login():
        db = SessionLocal()
        try:
            if request.method == "POST":
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "").strip()
                user = db.query(User).filter_by(username=username).first()
                if not user or not check_password_hash(user.password_hash, password):
                    flash("نام کاربری یا رمز عبور نادرست است.", "error")
                    return redirect(url_for("login"))

                ip = get_client_ip()
                if ip != user.registered_ip:
                    flash("این حساب فقط از همان IP ثبت‌نام قابل استفاده است.", "error")
                    return redirect(url_for("login"))

                login_user(user)
                flash("با موفقیت وارد شدید.", "success")
                return redirect(url_for("dashboard"))

            return render_template("login.html")
        finally:
            db.close()

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("خارج شدید.", "success")
        return redirect(url_for("index"))

    @app.route("/dashboard", methods=["GET", "POST"])
    @login_required
    def dashboard():
        db = SessionLocal()
        try:
            user = db.get(User, current_user.id)
            scanned = user.scanned_domains

            # Scan types مشابه منوی aesgis.sh (فقط مهم‌ترین‌ها)
            scan_types = [
                ("deep", "Deep Scan", "اسکن عمیق کامل (همه‌جانبه)"),
                ("normal", "Normal Scan", "اسکن عادی و سریع‌تر"),
                ("sqli", "SQL Injection", "تست ضعف‌های SQLi"),
                ("xss", "XSS", "تست Cross-Site Scripting"),
                ("port", "Port Scan", "اسکن پورت‌ها با C++"),
                ("dir_bruteforce", "Directory Bruteforce", "Bruteforce دایرکتوری‌ها و فایل‌ها"),
            ]

            if request.method == "POST":
                target_url = request.form.get("target_url", "").strip()
                scan_type = request.form.get("scan_type", "").strip()

                if not target_url or not scan_type:
                    flash("URL و نوع اسکن الزامی است.", "error")
                    return redirect(url_for("dashboard"))

                # دامنه را استخراج کن
                parsed = urlparse(target_url)
                domain = parsed.netloc or parsed.path
                domain = domain.lower()

                # محدودیت: هر کاربر فقط دو دامنه متفاوت
                unique_domains = set(scanned)
                if domain not in unique_domains and len(unique_domains) >= 2:
                    flash("هر حساب فقط می‌تواند دو سایت مختلف را تست کند.", "error")
                    return redirect(url_for("dashboard"))

                # اجرای اسکن
                output_dir = f"web_scan_results_{os.getpid()}"
                try:
                    result = run_scan_job(scan_type, target_url, output_dir)
                    if result.ok:
                        # ذخیره دامنه در پروفایل کاربر
                        if domain not in unique_domains:
                            scanned.append(domain)
                            user.scanned_domains = scanned
                            db.add(user)
                            db.commit()

                        return render_template(
                            "scan_result.html",
                            target_url=target_url,
                            scan_type=scan_type,
                            result=result,
                        )
                    flash(f"اسکن با خطا مواجه شد: {result.message}", "error")
                except Exception as e:  # noqa: BLE001
                    flash(f"خطا در اجرای اسکن: {e}", "error")

            return render_template(
                "dashboard.html",
                scan_types=scan_types,
                scanned_domains=scanned,
            )
        finally:
            db.close()

    return app


if __name__ == "__main__":
    # Allow running via: python -m aegisweb.app
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)


