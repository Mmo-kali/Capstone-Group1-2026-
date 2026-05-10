import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "app.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    schema_path = BASE_DIR / "schema.sql"
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(schema_path.read_text(encoding="utf-8"))
        _migrate_schema(conn)
        conn.commit()
    finally:
        conn.close()


def _table_columns(conn, table_name):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row[1] for row in rows}


def _ensure_column(conn, table_name, column_name, column_type):
    columns = _table_columns(conn, table_name)
    if column_name in columns:
        return
    conn.execute(
        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
    )


def _migrate_schema(conn):
    if "profiles" in {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}:
        _ensure_column(conn, "profiles", "username", "text")
        _ensure_column(conn, "profiles", "dc_fqdn", "text")
        _ensure_column(conn, "profiles", "profile_description", "text")

        columns = _table_columns(conn, "profiles")
        if "fqdn" in columns:
            conn.execute(
                """
                UPDATE profiles
                SET dc_fqdn = COALESCE(dc_fqdn, fqdn)
                """
            )
        if "description" in columns:
            conn.execute(
                """
                UPDATE profiles
                SET profile_description = COALESCE(profile_description, description)
                """
            )

    if "users" in {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}:
        _ensure_column(conn, "users", "kerberosHash", "text")
        _ensure_column(conn, "users", "asrepHash", "text")
        _ensure_column(conn, "users", "ntlmHash", "text")
        _ensure_column(conn, "users", "lastSet", "timestamp")


def fetch_profiles():
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT name, username, password, domain, dc_ip, dc_fqdn, profile_description
            FROM profiles
            ORDER BY name
            """
        ).fetchall()
    finally:
        conn.close()

    profiles = {}
    for row in rows:
        profiles[row["name"]] = {
            "username": row["username"],
            "password": row["password"],
            "domain": row["domain"],
            "dc_ip": row["dc_ip"],
            "dc_fqdn": row["dc_fqdn"],
            "profile_description": row["profile_description"],
        }
    return profiles


def get_profile(name):
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT name, username, password, domain, dc_ip, dc_fqdn, profile_description
            FROM profiles
            WHERE name = ?
            """,
            (name,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return None

    return {
        "username": row["username"],
        "password": row["password"],
        "domain": row["domain"],
        "dc_ip": row["dc_ip"],
        "dc_fqdn": row["dc_fqdn"],
        "profile_description": row["profile_description"],
    }


def upsert_profile(profile_name, profile_data):
    conn = get_db()
    try:
        cursor = conn.execute(
            """
            UPDATE profiles
            SET username = ?,
                password = ?,
                domain = ?,
                dc_ip = ?,
                dc_fqdn = ?,
                profile_description = ?
            WHERE name = ?
            """,
            (
                profile_data.get("username", ""),
                profile_data.get("password", ""),
                profile_data.get("domain", ""),
                profile_data.get("dc_ip", ""),
                profile_data.get("dc_fqdn", ""),
                profile_data.get("profile_description", ""),
                profile_name,
            ),
        )
        if cursor.rowcount == 0:
            conn.execute(
                """
                INSERT INTO profiles (
                    name,
                    username,
                    password,
                    domain,
                    dc_ip,
                    dc_fqdn,
                    profile_description
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile_name,
                    profile_data.get("username", ""),
                    profile_data.get("password", ""),
                    profile_data.get("domain", ""),
                    profile_data.get("dc_ip", ""),
                    profile_data.get("dc_fqdn", ""),
                    profile_data.get("profile_description", ""),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def get_active_profile():
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT value FROM app_state WHERE key = ?",
            ("active_profile",),
        ).fetchone()
    finally:
        conn.close()

    return row["value"] if row else None


def set_active_profile(profile_name):
    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO app_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            ("active_profile", profile_name),
        )
        conn.commit()
    finally:
        conn.close()


def clear_profiles():
    conn = get_db()
    try:
        conn.execute("DELETE FROM profiles")
        conn.execute(
            "DELETE FROM app_state WHERE key = ?",
            ("active_profile",),
        )
        conn.commit()
    finally:
        conn.close()


def user_exists(username):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ? LIMIT 1",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    return bool(row)


def upsert_user_hash(username, hash_field, hash_value, timestamp):
    if not username or not hash_field or not hash_value or not timestamp:
        return
    if hash_field not in {"kerberosHash", "asrepHash", "ntlmHash"}:
        return
    conn = get_db()
    try:
        cursor = conn.execute(
            f"UPDATE users SET {hash_field} = ?, lastSet = ? WHERE username = ?",
            (hash_value, timestamp, username),
        )
        if cursor.rowcount == 0:
            conn.execute(
                f"INSERT INTO users (username, {hash_field}, lastSet) VALUES (?, ?, ?)",
                (username, hash_value, timestamp),
            )
        conn.commit()
    finally:
        conn.close()


def update_user_password(username, password):
    if not username or not password:
        return
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (password, username),
        )
        conn.commit()
    finally:
        conn.close()


def clear_vault():
    conn = get_db()
    try:
        conn.execute("DELETE FROM users")
        conn.commit()
    finally:
        conn.close()


def fetch_vault_users():
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT username, kerberosHash, asrepHash, ntlmHash, password, lastSet
            FROM users
            ORDER BY username
            """
        ).fetchall()
    finally:
        conn.close()

    ui_blacklist = {"guest", "krbtgt"}

    def normalize_username(value):
        if not value:
            return value
        return value.split("\\", 1)[-1]

    entries_by_user = {}
    for row in rows:
        username = normalize_username(row["username"])
        if not username or username.lower() in ui_blacklist:
            continue
        entry = entries_by_user.get(username)

        if not entry:
            entry = {
                "username": username,
                "kerberos_hash": row["kerberosHash"],
                "asrep_hash": row["asrepHash"],
                "ntlm_hash": row["ntlmHash"],
                "password": row["password"],
                "timestamp": row["lastSet"],
            }
            entries_by_user[username] = entry
            continue

        if not entry.get("kerberos_hash") and row["kerberosHash"]:
            entry["kerberos_hash"] = row["kerberosHash"]
        if not entry.get("asrep_hash") and row["asrepHash"]:
            entry["asrep_hash"] = row["asrepHash"]
        if not entry.get("ntlm_hash") and row["ntlmHash"]:
            entry["ntlm_hash"] = row["ntlmHash"]
        if not entry.get("password") and row["password"]:
            entry["password"] = row["password"]

        existing_ts = entry.get("timestamp") or ""
        new_ts = row["lastSet"] or ""
        if new_ts > existing_ts:
            entry["timestamp"] = row["lastSet"]

    entries = []
    for entry in entries_by_user.values():
        entry["status"] = "Cracked" if entry.get("password") else "Uncracked"
        entries.append(entry)

    entries.sort(key=lambda item: (item.get("username") or ""))
    return entries

