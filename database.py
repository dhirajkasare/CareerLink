from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

import mysql.connector
from mysql.connector import Error

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

load_dotenv(Path(__file__).resolve().parent / ".env")

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "careerlink")
DB_SSL_MODE = os.getenv("DB_SSL_MODE", "").strip().upper()
DB_SSL_CA = os.getenv("DB_SSL_CA", "").strip()


def get_connection(use_database: bool = True) -> mysql.connector.MySQLConnection:
    config: Dict[str, Any] = {
        "host": DB_HOST,
        "port": DB_PORT,
        "user": DB_USER,
        "password": DB_PASSWORD,
    }
    if use_database:
        config["database"] = DB_NAME
    if DB_SSL_MODE:
        config["ssl_disabled"] = False
        if DB_SSL_MODE == "REQUIRED":
            config["ssl_verify_cert"] = False
            config["ssl_verify_identity"] = False
        elif DB_SSL_MODE in {"VERIFY_CA", "VERIFY_IDENTITY"} and DB_SSL_CA:
            config["ssl_ca"] = DB_SSL_CA
            config["ssl_verify_cert"] = True
            config["ssl_verify_identity"] = DB_SSL_MODE == "VERIFY_IDENTITY"

    try:
        return mysql.connector.connect(**config)
    except Error as error:
        raise RuntimeError(f"MySQL connection failed: {error}") from error


def initialize_database(password_hasher: Callable[[str], str]) -> None:
    create_database()
    create_tables()
    normalize_existing_data()
    seed_default_data(password_hasher)


def create_database() -> None:
    connection = get_connection(use_database=False)
    try:
        cursor = connection.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        connection.commit()
    finally:
        connection.close()


def create_tables() -> None:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL UNIQUE,
                phone VARCHAR(30) DEFAULT '',
                location VARCHAR(255) DEFAULT '',
                career_interests TEXT,
                linkedin VARCHAR(255) DEFAULT '',
                profile_image VARCHAR(500) DEFAULT '',
                profile_picture_url VARCHAR(500) DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                CONSTRAINT fk_profiles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255),
                company VARCHAR(255),
                location VARCHAR(255),
                skills TEXT,
                link TEXT,
                platform VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS resumes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                filename VARCHAR(255) NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_resumes_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS email_otps (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                purpose VARCHAR(50) NOT NULL,
                otp_hash VARCHAR(255) NOT NULL,
                user_name VARCHAR(255) DEFAULT '',
                expires_at DATETIME NOT NULL,
                consumed_at DATETIME NULL,
                request_ip VARCHAR(64) DEFAULT '',
                attempts INT NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email_otps_email_purpose (email, purpose),
                INDEX idx_email_otps_expires_at (expires_at)
            )
            """
        )
        connection.commit()
    finally:
        connection.close()


def normalize_existing_data() -> None:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("UPDATE users SET role = 'user' WHERE role = 'client'")
        cursor.execute(
            """
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'profiles' AND COLUMN_NAME = 'location'
            """,
            (DB_NAME,),
        )
        if cursor.fetchone()[0] == 0:
            cursor.execute("ALTER TABLE profiles ADD COLUMN location VARCHAR(255) DEFAULT '' AFTER phone")

        cursor.execute(
            """
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'profiles' AND COLUMN_NAME = 'career_interests'
            """,
            (DB_NAME,),
        )
        if cursor.fetchone()[0] == 0:
            cursor.execute("ALTER TABLE profiles ADD COLUMN career_interests TEXT AFTER location")

        cursor.execute(
            """
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'profiles' AND COLUMN_NAME = 'profile_image'
            """,
            (DB_NAME,),
        )
        if cursor.fetchone()[0] == 0:
            cursor.execute(
                "ALTER TABLE profiles ADD COLUMN profile_image VARCHAR(500) DEFAULT '' AFTER linkedin"
            )

        cursor.execute(
            """
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'profiles' AND COLUMN_NAME = 'profile_picture_url'
            """,
            (DB_NAME,),
        )
        if cursor.fetchone()[0] == 0:
            cursor.execute(
                "ALTER TABLE profiles ADD COLUMN profile_picture_url VARCHAR(500) DEFAULT '' AFTER linkedin"
            )

        cursor.execute(
            """
            UPDATE profiles
            SET profile_image = profile_picture_url
            WHERE COALESCE(profile_image, '') = '' AND COALESCE(profile_picture_url, '') <> ''
            """
        )

        cursor.execute(
            """
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'profiles' AND COLUMN_NAME = 'address'
            """,
            (DB_NAME,),
        )
        if cursor.fetchone()[0] > 0:
            cursor.execute(
                """
                UPDATE profiles
                SET location = COALESCE(NULLIF(location, ''), address)
                WHERE COALESCE(location, '') = '' AND COALESCE(address, '') <> ''
                """
            )

        job_column_sizes = {
            "title": 500,
            "company": 500,
            "location": 500,
            "platform": 150,
        }
        for column_name, target_length in job_column_sizes.items():
            cursor.execute(
                """
                SELECT CHARACTER_MAXIMUM_LENGTH
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'jobs' AND COLUMN_NAME = %s
                """,
                (DB_NAME, column_name),
            )
            result = cursor.fetchone()
            current_length = int(result[0]) if result and result[0] is not None else 0
            if current_length and current_length < target_length:
                cursor.execute(f"ALTER TABLE jobs MODIFY COLUMN {column_name} VARCHAR({target_length})")

        indexes = [
            ("jobs", "idx_jobs_location", "CREATE INDEX idx_jobs_location ON jobs (location)"),
            ("jobs", "idx_jobs_company", "CREATE INDEX idx_jobs_company ON jobs (company)"),
            ("jobs", "idx_jobs_platform", "CREATE INDEX idx_jobs_platform ON jobs (platform)"),
            ("users", "idx_users_role", "CREATE INDEX idx_users_role ON users (role)"),
            ("resumes", "idx_resumes_user_id", "CREATE INDEX idx_resumes_user_id ON resumes (user_id)"),
        ]
        for table_name, index_name, statement in indexes:
            cursor.execute(
                """
                SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND INDEX_NAME = %s
                """,
                (DB_NAME, table_name, index_name),
            )
            if cursor.fetchone()[0] == 0:
                cursor.execute(statement)
        connection.commit()
    finally:
        connection.close()


def seed_default_data(password_hasher: Callable[[str], str]) -> None:
    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    if not admin_email or not admin_password:
        return

    existing_admin = fetch_one("SELECT id FROM users WHERE role = %s", ("admin",))
    if not existing_admin:
        admin_id = execute_query(
            """
            INSERT INTO users (name, email, password_hash, role)
            VALUES (%s, %s, %s, %s)
            """,
            ("System Admin", admin_email, password_hasher(admin_password), "admin"),
            return_lastrowid=True,
        )
        execute_query(
            """
            INSERT INTO profiles (user_id, phone, location, career_interests, linkedin, profile_picture_url)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (admin_id, "", "", "", "", ""),
        )
    else:
        execute_query(
            """
            UPDATE users
            SET name = %s, email = %s, password_hash = %s
            WHERE id = %s
            """,
            ("System Admin", admin_email, password_hasher(admin_password), existing_admin["id"]),
        )


def fetch_all(query: str, params: Optional[Iterable[Any]] = None) -> List[Dict[str, Any]]:
    connection = get_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, tuple(params or ()))
        return cursor.fetchall()
    finally:
        connection.close()


def fetch_one(query: str, params: Optional[Iterable[Any]] = None) -> Optional[Dict[str, Any]]:
    connection = get_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, tuple(params or ()))
        return cursor.fetchone()
    finally:
        connection.close()


def execute_query(
    query: str,
    params: Optional[Iterable[Any]] = None,
    *,
    return_lastrowid: bool = False,
) -> Optional[int]:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(query, tuple(params or ()))
        connection.commit()
        if return_lastrowid:
            return cursor.lastrowid
        return None
    finally:
        connection.close()


def execute_many(query: str, params_list: Iterable[Iterable[Any]]) -> None:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.executemany(query, [tuple(params) for params in params_list])
        connection.commit()
    finally:
        connection.close()
