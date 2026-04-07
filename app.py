import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DB_PATH = INSTANCE_DIR / "lost_found.sqlite3"

STATUSES = ("Найдено", "Забрано")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    ensure_default_admin()

    @app.before_request
    def load_user():
        uid = session.get("user_id")
        g.user = None
        if uid is not None:
            g.user = query_one(
                "SELECT id, username, role FROM users WHERE id = ?", (uid,)
            )

    @app.get("/")
    def index():
        return redirect(url_for("items_list"))

    @app.get("/items")
    @login_required
    def items_list():
        rows = query_all(
            """
            SELECT
              fi.id,
              fi.title,
              fi.description,
              fi.date_found,
              fi.place,
              (
                SELECT sl.status
                FROM status_log sl
                WHERE sl.found_item_id = fi.id
                ORDER BY datetime(sl.created_at) DESC, sl.id DESC
                LIMIT 1
              ) AS current_status
            FROM found_items fi
            ORDER BY datetime(fi.date_found) DESC, fi.id DESC
            """
        )
        for r in rows:
            if not r.get("current_status"):
                r["current_status"] = "Найдено"
            if r["current_status"] == "Передано":
                r["current_status"] = "Забрано"
        return render_template("items.html", items=rows)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("items_list"))
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            u = query_one(
                "SELECT id, password_hash, role FROM users WHERE username = ?",
                (username,),
            )
            if not u or not check_password_hash(u["password_hash"], password):
                flash("Неверный логин или пароль.")
                return render_template("login.html")
            session.clear()
            session["user_id"] = u["id"]
            flash("Добро пожаловать.")
            return redirect(url_for("items_list"))
        return render_template("login.html")

    @app.get("/logout")
    def logout():
        session.clear()
        flash("Вы вышли.")
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("items_list"))
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            if not username:
                flash("Укажите логин.")
                return render_template("register.html")
            if len(password) < 4:
                flash("Пароль не короче 4 символов.")
                return render_template("register.html")
            try:
                execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                    (username, generate_password_hash(password)),
                )
            except sqlite3.IntegrityError:
                flash("Такой логин уже занят.")
                return render_template("register.html")
            flash("Регистрация успешна. Войдите.")
            return redirect(url_for("login"))
        return render_template("register.html")

    # --- Админ: находки ---
    @app.route("/admin/items/new", methods=["GET", "POST"])
    @admin_required
    def admin_item_new():
        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            description = (request.form.get("description") or "").strip()
            date_found = (request.form.get("date_found") or "").strip()
            place = (request.form.get("place") or "").strip()
            if not title or not date_found or not place:
                flash("Заполните название, дату и место.")
                return render_template("admin_item_form.html", item=None, mode="new")
            db = get_db()
            cur = db.execute(
                """
                INSERT INTO found_items (title, description, date_found, place)
                VALUES (?, ?, ?, ?)
                """,
                (title, description, date_found, place),
            )
            item_id = cur.lastrowid
            db.execute(
                "INSERT INTO status_log (found_item_id, status) VALUES (?, 'Найдено')",
                (item_id,),
            )
            db.commit()
            flash("Запись добавлена.")
            return redirect(url_for("items_list"))
        return render_template("admin_item_form.html", item=None, mode="new")

    @app.route("/admin/items/<int:item_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_item_edit(item_id: int):
        item = query_one(
            """
            SELECT fi.id, fi.title, fi.description, fi.date_found, fi.place
            FROM found_items fi WHERE fi.id = ?
            """,
            (item_id,),
        )
        if not item:
            flash("Запись не найдена.")
            return redirect(url_for("items_list"))
        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            description = (request.form.get("description") or "").strip()
            date_found = (request.form.get("date_found") or "").strip()
            place = (request.form.get("place") or "").strip()
            if not title or not date_found or not place:
                flash("Заполните название, дату и место.")
                merged = dict(item)
                merged.update(request.form)
                return render_template("admin_item_form.html", item=merged, mode="edit")
            execute(
                """
                UPDATE found_items
                SET title = ?, description = ?, date_found = ?, place = ?
                WHERE id = ?
                """,
                (title, description, date_found, place, item_id),
            )
            flash("Данные обновлены.")
            return redirect(url_for("items_list"))
        return render_template("admin_item_form.html", item=item, mode="edit")

    @app.post("/admin/items/<int:item_id>/delete")
    @admin_required
    def admin_item_delete(item_id: int):
        execute("DELETE FROM found_items WHERE id = ?", (item_id,))
        flash("Запись удалена.")
        return redirect(url_for("items_list"))

    @app.route("/admin/items/<int:item_id>/status", methods=["GET", "POST"])
    @admin_required
    def admin_item_status(item_id: int):
        item = query_one(
            "SELECT id, title FROM found_items WHERE id = ?", (item_id,)
        )
        if not item:
            flash("Запись не найдена.")
            return redirect(url_for("items_list"))
        history = query_all(
            """
            SELECT status, created_at
            FROM status_log
            WHERE found_item_id = ?
            ORDER BY datetime(created_at) DESC, id DESC
            """,
            (item_id,),
        )
        if request.method == "POST":
            status = (request.form.get("status") or "").strip()
            if status not in STATUSES:
                flash("Выберите статус из списка.")
                return render_template(
                    "admin_item_status.html",
                    item=item,
                    history=history,
                    statuses=STATUSES,
                )
            execute(
                "INSERT INTO status_log (found_item_id, status) VALUES (?, ?)",
                (item_id, status),
            )
            flash("Статус зафиксирован.")
            return redirect(url_for("items_list"))
        return render_template(
            "admin_item_status.html",
            item=item,
            history=history,
            statuses=STATUSES,
        )

    return app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        g.db = conn
    return g.db


def query_one(sql: str, params: tuple = ()):
    cur = get_db().execute(sql, params)
    row = cur.fetchone()
    cur.close()
    return dict(row) if row else None


def query_all(sql: str, params: tuple = ()):
    cur = get_db().execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    return [dict(r) for r in rows]


def execute(sql: str, params: tuple = ()) -> None:
    db = get_db()
    db.execute(sql, params)
    db.commit()


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cabinet TEXT NOT NULL,
            floor TEXT NOT NULL DEFAULT '',
            building TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS found_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            date_found TEXT NOT NULL,
            place TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS status_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            found_item_id INTEGER NOT NULL REFERENCES found_items(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK (status IN ('Найдено', 'Забрано')),
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """
    )
    columns = [r[1] for r in conn.execute("PRAGMA table_info(found_items)").fetchall()]
    if "place" not in columns:
        conn.execute("ALTER TABLE found_items ADD COLUMN place TEXT NOT NULL DEFAULT ''")
    conn.execute("UPDATE status_log SET status = 'Забрано' WHERE status = 'Передано'")
    conn.commit()
    conn.close()


def ensure_default_admin() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    if cur.fetchone() is None:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            ("admin", generate_password_hash("admin")),
        )
        conn.commit()
    cur.close()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        if g.user.get("role") != "admin":
            flash("Нужны права администратора.")
            return redirect(url_for("items_list"))
        return view(**kwargs)

    return wrapped


app = create_app()


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


if __name__ == "__main__":
    app.run(debug=True)
