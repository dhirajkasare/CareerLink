from __future__ import annotations

import json
import os
import re
import secrets
import smtplib
import tempfile
import csv
import time
from collections import Counter
from datetime import datetime, timedelta
from email.message import EmailMessage
from smtplib import SMTPAuthenticationError, SMTPException
from functools import lru_cache, wraps
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import pandas as pd
import pdfplumber
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from mysql.connector import DataError as MySQLDataError
from pdfminer.pdfparser import PDFSyntaxError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from database import execute_many, execute_query, fetch_all, fetch_one, initialize_database

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

try:
    import google.generativeai as google_generativeai
except ImportError:
    google_generativeai = None

try:
    from google import genai

except ImportError:
    genai = None

try:
    from groq import Groq
except ImportError:
    Groq = None

try:
    import spacy
except ImportError:
    spacy = None

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
except ImportError:
    TfidfVectorizer = None

GEMINI_AVAILABLE = bool(google_generativeai or genai)
GROQ_AVAILABLE = Groq is not None
SPACY_AVAILABLE = spacy is not None
SKLEARN_AVAILABLE = TfidfVectorizer is not None

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def clear_dead_local_proxy_settings() -> None:
    proxy_names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
    dead_proxy_hosts = ("127.0.0.1:9", "localhost:9")

    for proxy_name in proxy_names:
        proxy_value = os.environ.get(proxy_name, "")
        if any(dead_host in proxy_value for dead_host in dead_proxy_hosts):
            os.environ.pop(proxy_name, None)


clear_dead_local_proxy_settings()

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = str(BASE_DIR / "static" / "uploads")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

PROFILE_UPLOAD_DIR = BASE_DIR / "static" / "uploads" / "profiles"
PROFILE_IMAGE_WEB_DIR = "/static/uploads/profiles"
ALLOWED_PROFILE_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png"}

GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY", "")
gemini_client = genai.Client(api_key=GEMINI_API_KEY) if genai and GEMINI_API_KEY else None
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
groq_client = Groq(api_key=GROQ_API_KEY) if Groq and GROQ_API_KEY else None
GEMINI_RESUME_MODEL = os.getenv("GEMINI_RESUME_MODEL", "gemini-2.5-flash")
GEMINI_FRAUD_MODEL = os.getenv("GEMINI_FRAUD_MODEL", "gemini-2.5-flash")
GROQ_RESUME_MODEL = os.getenv("GROQ_RESUME_MODEL", "openai/gpt-oss-120b")
GROQ_FRAUD_MODEL = os.getenv("GROQ_FRAUD_MODEL", "openai/gpt-oss-120b")
GROQ_CHAT_MODEL = os.getenv("GROQ_CHAT_MODEL", "llama-3.1-8b-instant")
GEMINI_MAX_RETRIES = 3
GEMINI_RETRY_BASE_DELAY_SECONDS = 1.5
GROQ_MAX_RETRIES = 2
GROQ_RETRY_BASE_DELAY_SECONDS = 1.2
ALLOWED_RESUME_EXTENSIONS = {"pdf"}
MAX_RESUME_TEXT_CHARS = 24000
MAX_REDUCED_TEXT_CHARS = 7000
MAX_CHAT_TEXT_CHARS = 2500
MAX_KEYWORDS = 28
MAX_SELECTED_SENTENCES = 18
ADMIN_JOBS_PAGE_SIZE = 50
JOB_RESULTS_PAGE_SIZE = 12
OTP_EXPIRY_MINUTES = 5
OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "45"))
OTP_MAX_REQUESTS_PER_HOUR = int(os.getenv("OTP_MAX_REQUESTS_PER_HOUR", "5"))
OTP_MAX_VERIFY_ATTEMPTS = int(os.getenv("OTP_MAX_VERIFY_ATTEMPTS", "5"))
OTP_PEPPER = os.getenv("OTP_PEPPER") or app.config["SECRET_KEY"]
MAIL_PROVIDER = os.getenv("MAIL_PROVIDER", "gmail").strip().lower()
MAIL_SERVER = os.getenv("MAIL_SERVER") or ("smtp.gmail.com" if MAIL_PROVIDER == "gmail" else "")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
MAIL_FROM = os.getenv("MAIL_FROM") or MAIL_USERNAME

COMMON_SKILLS = [
    "python",
    "java",
    "sql",
    "machine learning",
    "deep learning",
    "data analysis",
    "flask",
    "django",
    "aws",
    "docker",
    "javascript",
    "react",
    "html",
    "css",
]

FRAUD_ANALYSIS_SCHEMA: Dict[str, Any] = {
    "name": "fraud_analysis",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "classification": {
                "type": "string",
                "enum": ["FAKE", "LEGITIMATE"],
            },
            "risk_score": {"type": "number"},
            "confidence": {"type": "number"},
            "scam_indicators": {
                "type": "array",
                "items": {"type": "string"},
            },
            "company_analysis": {
                "type": "object",
                "properties": {
                    "company_present": {"type": "boolean"},
                    "company_verifiable": {"type": "boolean"},
                },
                "required": ["company_present", "company_verifiable"],
                "additionalProperties": False,
            },
            "contact_analysis": {
                "type": "object",
                "properties": {
                    "uses_free_email": {"type": "boolean"},
                    "uses_messaging_apps": {"type": "boolean"},
                },
                "required": ["uses_free_email", "uses_messaging_apps"],
                "additionalProperties": False,
            },
            "salary_analysis": {
                "type": "object",
                "properties": {
                    "salary_present": {"type": "boolean"},
                    "salary_unrealistic": {"type": "boolean"},
                },
                "required": ["salary_present", "salary_unrealistic"],
                "additionalProperties": False,
            },
            "text_quality": {
                "type": "object",
                "properties": {
                    "grammar_quality": {
                        "type": "string",
                        "enum": ["good", "moderate", "poor"],
                    },
                    "generic_description": {"type": "boolean"},
                },
                "required": ["grammar_quality", "generic_description"],
                "additionalProperties": False,
            },
            "explanation": {"type": "string"},
            "recommended_action": {
                "type": "string",
                "enum": ["safe", "caution", "avoid"],
            },
        },
        "required": [
            "classification",
            "risk_score",
            "confidence",
            "scam_indicators",
            "company_analysis",
            "contact_analysis",
            "salary_analysis",
            "text_quality",
            "explanation",
            "recommended_action",
        ],
        "additionalProperties": False,
    },
}

RESUME_ANALYSIS_TEMPLATE: Dict[str, Any] = {
    "resume_score": 0,
    "summary": "",
    "strengths": [],
    "weaknesses": [],
    "missing_sections": [],
    "improvement_tips": [],
    "suggested_skills": [],
}

JOB_CSV_REQUIRED_COLUMNS = ["title", "company", "location", "skills", "link", "platform"]
JOB_FIELD_MAX_LENGTHS = {
    "title": 500,
    "company": 500,
    "location": 500,
    "platform": 150,
}
PLATFORM_LOGO_FILES = {
    "instahyre": "platform logos/instahyre.png",
    "apna": "platform logos/apna.png",
    "internshala": "platform logos/internshala.png",
    "shine": "platform logos/shine.png",
}

CAREERLINK_SUPPORT_PROMPT = """You are the AI assistant for CareerLink, an AI Powered Smart Career Intelligence System.

Your job is to help users understand and use the CareerLink website.

Important response rules:
- Reply in simple plain text only.
- Do not use bold text, markdown, bullet symbols, decorative characters, emojis, or beautified formatting.
- Do not use stars, hashtags, long separators, or special styling.
- Keep replies short, clear, and practical.
- Prefer direct guidance with simple steps when the user asks how to do something.
- If the question is outside CareerLink, gently bring the answer back to CareerLink features.

CareerLink purpose:
CareerLink helps job seekers find relevant jobs, analyze resumes, detect fraudulent job postings, and understand job market trends.

Main modules:
Home
Jobs
Resume Analyzer
Fraud Detection
Market Insights

Feature summary:
Home: users can log in with User Login or create an account.
Jobs: users enter both skills and preferred location, then generate recommendations. Results appear as job cards with title, company, location, required skills, platform, and a View button.
Resume Analyzer: users upload a PDF resume and receive AI feedback such as resume score, summary, strengths, weaknesses, missing sections, and improvement suggestions.
Fraud Detection: users paste a job description and receive risk indicators, explanation, and a recommendation such as Safe to apply, Proceed with caution, or Avoid this job posting.
Market Insights: users can view hiring trends, demanded skills, top companies, total jobs, and location distribution through charts.

Your role:
Answer questions about how CareerLink works.
Guide users to the correct module.
Explain features clearly.
Help users complete tasks on the platform.
Suggest the most useful CareerLink feature based on the user's goal.

Response style:
Helpful, friendly, professional, concise, and easy to understand.
Avoid technical jargon unless necessary.
Do not act like a general chatbot. Focus on CareerLink."""

GENERIC_RESUME_HEADINGS = {
    "summary",
    "profile",
    "objective",
    "education",
    "experience",
    "work experience",
    "projects",
    "skills",
    "technical skills",
    "certifications",
    "achievements",
    "internships",
}


@lru_cache(maxsize=1)
def get_spacy_nlp():
    if not SPACY_AVAILABLE:
        return None

    model_candidates = ("en_core_web_sm", "en_core_web_md")
    for model_name in model_candidates:
        try:
            return spacy.load(model_name, disable=["parser", "textcat"])
        except Exception:
            continue

    try:
        nlp = spacy.blank("en")
        if "sentencizer" not in nlp.pipe_names:
            nlp.add_pipe("sentencizer")
        return nlp
    except Exception:
        return None


def normalize_text_whitespace(text: str) -> str:
    cleaned = str(text or "")
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def parse_model_priority_list(raw_value: str, fallback_models: List[str]) -> List[str]:
    models: List[str] = []
    for item in str(raw_value or "").split(","):
        model = item.strip()
        if model and model not in models:
            models.append(model)

    for item in fallback_models:
        model = str(item).strip()
        if model and model not in models:
            models.append(model)

    return models


def extract_regex_signals(text: str) -> List[str]:
    patterns = {
        "emails": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "phones": r"(?:\+?\d[\d\-\s()]{7,}\d)",
        "urls": r"https?://\S+|www\.\S+",
        "salary_values": r"(?:rs\.?|inr|\$|usd)?\s?\d[\d,]*(?:\s?(?:lpa|lac|lakhs?|k|m|per month|/month|per year|/year))?",
        "percentages": r"\b\d{1,3}%\b",
        "messaging_apps": r"\b(?:whatsapp|telegram|signal)\b",
        "payments": r"\b(?:upi|crypto|bitcoin|gift card|processing fee|registration fee|security deposit)\b",
    }

    signals: List[str] = []
    seen: set[str] = set()

    for label, pattern in patterns.items():
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            item = f"{label}: {str(match).strip()}"
            if item not in seen:
                signals.append(item)
                seen.add(item)
            if len(signals) >= 20:
                return signals
    return signals


def split_text_units(text: str) -> List[str]:
    normalized = normalize_text_whitespace(text)
    if not normalized:
        return []

    nlp = get_spacy_nlp()
    if nlp:
        try:
            doc = nlp(normalized[:MAX_RESUME_TEXT_CHARS])
            sentences = [sent.text.strip() for sent in getattr(doc, "sents", []) if sent.text.strip()]
            if sentences:
                return sentences
        except Exception:
            pass

    return [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", normalized) if part.strip()]


def extract_spacy_keywords(text: str, max_keywords: int = MAX_KEYWORDS) -> List[str]:
    normalized = normalize_text_whitespace(text)
    if not normalized:
        return []

    nlp = get_spacy_nlp()
    if not nlp:
        return []

    try:
        doc = nlp(normalized[:MAX_RESUME_TEXT_CHARS])
    except Exception:
        return []

    keyword_scores: Counter[str] = Counter()
    for token in doc:
        token_text = token.text.strip().lower()
        if not token_text or token.is_space or token.is_punct or token.is_stop:
            continue
        if len(token_text) < 3 or token.like_num:
            continue
        lemma = getattr(token, "lemma_", "") or token_text
        keyword_scores[lemma.lower()] += 2 if token_text in COMMON_SKILLS else 1

    for ent in getattr(doc, "ents", []):
        ent_text = ent.text.strip().lower()
        if ent_text and len(ent_text) > 2:
            keyword_scores[ent_text] += 2

    return [keyword for keyword, _ in keyword_scores.most_common(max_keywords)]


def extract_tfidf_keywords(text: str, max_keywords: int = MAX_KEYWORDS) -> List[str]:
    normalized = normalize_text_whitespace(text)
    if not normalized or not SKLEARN_AVAILABLE:
        return []

    units = split_text_units(normalized)
    documents = units if len(units) >= 2 else [normalized]

    try:
        vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=150)
        matrix = vectorizer.fit_transform(documents)
        scores = matrix.sum(axis=0).A1
        features = vectorizer.get_feature_names_out()
        ranked = sorted(zip(features, scores), key=lambda item: item[1], reverse=True)
    except Exception:
        return []

    keywords: List[str] = []
    for feature, _ in ranked:
        item = feature.strip().lower()
        if len(item) < 3 or item in keywords:
            continue
        keywords.append(item)
        if len(keywords) >= max_keywords:
            break
    return keywords


def select_key_lines(text: str, keywords: List[str], max_sentences: int = MAX_SELECTED_SENTENCES) -> List[str]:
    units = split_text_units(text)
    if not units:
        return []

    keyword_set = {keyword.lower() for keyword in keywords}
    scored_units: List[Tuple[int, int, str]] = []

    for index, unit in enumerate(units):
        lower_unit = unit.lower()
        score = 0

        for keyword in keyword_set:
            if keyword and keyword in lower_unit:
                score += 2 if " " in keyword else 1

        if re.search(r"\b(?:project|experience|education|skills|certification|salary|company|apply|contact)\b", lower_unit):
            score += 2
        if re.search(r"\b(?:whatsapp|telegram|gmail|outlook|urgent|fee|deposit|crypto)\b", lower_unit):
            score += 3
        if re.search(r"\d", unit):
            score += 1
        if any(lower_unit == heading or lower_unit.startswith(f"{heading}:") for heading in GENERIC_RESUME_HEADINGS):
            score += 1

        if score > 0:
            scored_units.append((score, -index, unit))

    if not scored_units:
        return units[:max_sentences]

    scored_units.sort(reverse=True)
    selected = [unit for _, _, unit in scored_units[:max_sentences]]
    ordered = [unit for unit in units if unit in selected]
    return ordered[:max_sentences]


def reduce_text_for_llm(text: str, context_label: str, max_chars: int = MAX_REDUCED_TEXT_CHARS) -> str:
    normalized = normalize_text_whitespace(text)
    if not normalized:
        return ""

    regex_signals = extract_regex_signals(normalized)
    keywords: List[str] = []
    for item in extract_spacy_keywords(normalized) + extract_tfidf_keywords(normalized):
        if item not in keywords:
            keywords.append(item)
        if len(keywords) >= MAX_KEYWORDS:
            break

    selected_lines = select_key_lines(normalized, keywords)
    sections = [
        f"{context_label} length: {len(normalized)} characters",
        f"Top keywords: {', '.join(keywords[:MAX_KEYWORDS]) or 'None detected'}",
        f"Regex signals: {' | '.join(regex_signals) if regex_signals else 'None detected'}",
        "Key lines:",
        "\n".join(f"- {line}" for line in selected_lines[:MAX_SELECTED_SENTENCES]),
    ]
    reduced = "\n".join(section for section in sections if section.strip()).strip()

    if len(reduced) <= max_chars:
        return reduced

    truncated_lines: List[str] = []
    total_length = 0
    for line in selected_lines:
        candidate = f"- {line}"
        if total_length + len(candidate) > max_chars // 2:
            break
        truncated_lines.append(candidate)
        total_length += len(candidate)

    compact_sections = [
        f"{context_label} length: {len(normalized)} characters",
        f"Top keywords: {', '.join(keywords[:18]) or 'None detected'}",
        f"Regex signals: {' | '.join(regex_signals[:10]) if regex_signals else 'None detected'}",
        "Key lines:",
        "\n".join(truncated_lines),
    ]
    return "\n".join(section for section in compact_sections if section.strip())[:max_chars].strip()


def ensure_upload_directory() -> Path:
    upload_dir = BASE_DIR / app.config["UPLOAD_FOLDER"]
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


def normalize_platform_name(platform: Any) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "", str(platform or "").strip().lower())
    return normalized


def enrich_job_cards(jobs_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched_jobs: List[Dict[str, Any]] = []
    for job in jobs_data:
        job_data = dict(job)
        normalized_platform = normalize_platform_name(job_data.get("platform", ""))
        logo_file = PLATFORM_LOGO_FILES.get(normalized_platform, "")
        job_data["platform_logo_url"] = url_for("static", filename=logo_file) if logo_file else ""
        job_data["platform_label"] = str(job_data.get("platform", "")).strip() or "Platform"
        enriched_jobs.append(job_data)
    return enriched_jobs


def allowed_resume_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_RESUME_EXTENSIONS


def allowed_profile_image_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_PROFILE_IMAGE_EXTENSIONS


def resolve_profile_image_url(profile: Optional[Dict[str, Any]]) -> str:
    if not profile:
        return ""

    image_path = str(profile.get("profile_image") or "").strip()
    if image_path:
        return image_path

    legacy_image_path = str(profile.get("profile_picture_url") or "").strip()
    if legacy_image_path:
        return legacy_image_path

    return ""


def save_profile_image(file_storage: Any) -> str:
    original_name = secure_filename(file_storage.filename or "")
    if not original_name or not allowed_profile_image_file(original_name):
        raise ValueError("Please upload a JPG or PNG image.")

    extension = original_name.rsplit(".", 1)[1].lower()
    unique_filename = f"{uuid4().hex}.{extension}"
    PROFILE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    file_storage.save(PROFILE_UPLOAD_DIR / unique_filename)
    return f"{PROFILE_IMAGE_WEB_DIR}/{unique_filename}"


def parse_job_csv(csv_file) -> List[Dict[str, str]]:
    try:
        content = csv_file.read().decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("CSV file must be UTF-8 encoded.") from error

    reader = csv.DictReader(StringIO(content))
    if not reader.fieldnames:
        raise ValueError("CSV file is empty or missing a header row.")

    normalized_fieldnames = [str(fieldname).strip().lower() for fieldname in reader.fieldnames if fieldname]
    missing_columns = [column for column in JOB_CSV_REQUIRED_COLUMNS if column not in normalized_fieldnames]
    if missing_columns:
        raise ValueError(
            "Missing required CSV columns: "
            + ", ".join(missing_columns)
            + ". Required columns are: "
            + ", ".join(JOB_CSV_REQUIRED_COLUMNS)
        )

    normalized_rows: List[Dict[str, str]] = []
    for row_number, row in enumerate(reader, start=2):
        if None in row:
            raise ValueError(
                f"Row {row_number} has extra comma-separated values. If any field contains commas, wrap that cell in double quotes."
            )

        normalized_row = {str(key).strip().lower(): str(value or "").strip() for key, value in row.items() if key}
        if not any(normalized_row.values()):
            continue

        missing_values = [column for column in JOB_CSV_REQUIRED_COLUMNS if not normalized_row.get(column, "")]
        if missing_values:
            raise ValueError(
                f"Row {row_number} is missing values for: {', '.join(missing_values)}."
            )

        validate_job_payload(normalized_row, row_number=row_number)
        normalized_rows.append({column: normalized_row[column] for column in JOB_CSV_REQUIRED_COLUMNS})

    if not normalized_rows:
        raise ValueError("CSV file does not contain any valid job rows.")

    return normalized_rows


def validate_job_payload(job_data: Dict[str, str], *, row_number: Optional[int] = None) -> None:
    prefix = f"Row {row_number}: " if row_number is not None else ""

    for field_name in JOB_CSV_REQUIRED_COLUMNS:
        if not str(job_data.get(field_name, "")).strip():
            raise ValueError(f"{prefix}{field_name} is required.")

    for field_name, max_length in JOB_FIELD_MAX_LENGTHS.items():
        field_value = str(job_data.get(field_name, "")).strip()
        if len(field_value) > max_length:
            raise ValueError(
                f"{prefix}{field_name} is too long ({len(field_value)} characters). Maximum allowed is {max_length}."
            )


def load_jobs(limit: Optional[int] = None) -> pd.DataFrame:
    params: List[Any] = []
    limit_clause = ""
    if limit is not None:
        limit_clause = "LIMIT %s"
        params.append(int(limit))

    rows = fetch_all(
        f"""
        SELECT id, title, company, location, skills, link, platform, created_at, updated_at
        FROM jobs
        ORDER BY id DESC
        {limit_clause}
        """,
        params,
    )
    columns = ["id", "title", "company", "location", "skills", "link", "platform", "created_at", "updated_at"]
    if not rows:
        return pd.DataFrame(columns=columns)
    return pd.DataFrame(rows, columns=columns).fillna("")


def count_jobs() -> int:
    result = fetch_one("SELECT COUNT(*) AS count FROM jobs")
    return int((result or {}).get("count", 0))


def fetch_featured_jobs(limit: int = 3) -> List[Dict[str, Any]]:
    return fetch_all(
        """
        SELECT id, title, company, location, skills, link, platform, created_at, updated_at
        FROM jobs
        ORDER BY id DESC
        LIMIT %s
        """,
        (limit,),
    )


def fetch_admin_jobs_page(page: int, per_page: int) -> List[Dict[str, Any]]:
    offset = max(0, (page - 1) * per_page)
    return fetch_all(
        """
        SELECT id, title, company, location, skills, platform, link
        FROM jobs
        ORDER BY id DESC
        LIMIT %s OFFSET %s
        """,
        (per_page, offset),
    )


def build_pagination(current_page: int, total_pages: int) -> List[Optional[int]]:
    if total_pages <= 7:
        return list(range(1, total_pages + 1))

    pages = {1, total_pages, current_page - 1, current_page, current_page + 1}
    valid_pages = sorted(page for page in pages if 1 <= page <= total_pages)

    pagination: List[Optional[int]] = []
    previous_page: Optional[int] = None
    for page in valid_pages:
        if previous_page is not None and page - previous_page > 1:
            pagination.append(None)
        pagination.append(page)
        previous_page = page

    return pagination


def load_users() -> List[Dict[str, Any]]:
    return fetch_all(
        """
        SELECT id, name, email, role, created_at
        FROM users
        ORDER BY id DESC
        """
    )


def load_resumes() -> List[Dict[str, Any]]:
    return fetch_all(
        """
        SELECT id, user_id, filename, uploaded_at
        FROM resumes
        ORDER BY id DESC
        """
    )


def query_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    return fetch_one("SELECT * FROM users WHERE email = %s", (email,))


def query_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    return fetch_one("SELECT * FROM users WHERE id = %s", (user_id,))


def query_profile_by_user_id(user_id: int) -> Optional[Dict[str, Any]]:
    return fetch_one("SELECT * FROM profiles WHERE user_id = %s", (user_id,))


def normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def is_valid_email(email: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))


def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp: str) -> str:
    return generate_password_hash(f"{otp}:{OTP_PEPPER}")


def check_otp_hash(otp_hash: str, otp: str) -> bool:
    return check_password_hash(otp_hash, f"{otp}:{OTP_PEPPER}")


def cleanup_expired_otps() -> None:
    execute_query(
        """
        DELETE FROM email_otps
        WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 1 DAY
           OR consumed_at IS NOT NULL
        """
    )


def get_client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()[:64]
    return (request.remote_addr or "")[:64]


def latest_pending_otp(email: str, purpose: str) -> Optional[Dict[str, Any]]:
    return fetch_one(
        """
        SELECT *
        FROM email_otps
        WHERE email = %s
          AND purpose = %s
          AND consumed_at IS NULL
          AND expires_at > UTC_TIMESTAMP()
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (email, purpose),
    )


def can_send_otp(email: str, purpose: str) -> Tuple[bool, str]:
    recent_otp_cooldown = fetch_one(
        """
        SELECT GREATEST(0, %s - TIMESTAMPDIFF(SECOND, created_at, UTC_TIMESTAMP())) AS remaining_seconds
        FROM email_otps
        WHERE email = %s
          AND purpose = %s
          AND consumed_at IS NULL
          AND expires_at > UTC_TIMESTAMP()
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (OTP_RESEND_COOLDOWN_SECONDS, email, purpose),
    )
    remaining_seconds = int((recent_otp_cooldown or {}).get("remaining_seconds", 0) or 0)
    if remaining_seconds > 0:
        return False, f"Please wait {remaining_seconds} seconds before requesting another OTP."

    request_count = fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM email_otps
        WHERE email = %s
          AND purpose = %s
          AND created_at > UTC_TIMESTAMP() - INTERVAL 1 HOUR
        """,
        (email, purpose),
    )
    if int((request_count or {}).get("count", 0)) >= OTP_MAX_REQUESTS_PER_HOUR:
        return False, "Too many OTP requests. Please try again later."

    return True, ""


def send_otp_email(email: str, otp: str, purpose: str) -> None:
    if not MAIL_SERVER or not MAIL_USERNAME or not MAIL_PASSWORD or not MAIL_FROM:
        raise RuntimeError("Email service is not configured. Please set SMTP environment variables.")

    purpose_label = "sign in" if purpose == "login" else "create your account"
    message = EmailMessage()
    message["Subject"] = "Your CareerLink verification code"
    message["From"] = MAIL_FROM
    message["To"] = email
    message.set_content(
        "\n".join(
            [
                f"Your CareerLink OTP is {otp}.",
                "",
                f"Use this code to {purpose_label}. It expires in {OTP_EXPIRY_MINUTES} minutes.",
                "If you did not request this code, you can ignore this email.",
            ]
        )
    )

    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=15) as smtp:
            if MAIL_USE_TLS:
                smtp.starttls()
            smtp.login(MAIL_USERNAME, MAIL_PASSWORD)
            smtp.send_message(message)
    except SMTPAuthenticationError as error:
        raise RuntimeError(
            "OTP email could not be sent because Gmail SMTP login failed. Check MAIL_USERNAME and use a Gmail App Password in MAIL_PASSWORD."
        ) from error
    except SMTPException as error:
        raise RuntimeError(f"OTP email could not be sent. SMTP error: {error}") from error
    except OSError as error:
        raise RuntimeError(f"OTP email could not be sent. Network error: {error}") from error


def create_otp_challenge(email: str, purpose: str, user_name: str = "") -> Tuple[bool, str]:
    cleanup_expired_otps()
    allowed, error = can_send_otp(email, purpose)
    if not allowed:
        return False, error

    otp = generate_otp()
    send_otp_email(email, otp, purpose)
    execute_query(
        """
        INSERT INTO email_otps (email, purpose, otp_hash, user_name, expires_at, request_ip)
        VALUES (%s, %s, %s, %s, UTC_TIMESTAMP() + INTERVAL %s MINUTE, %s)
        """,
        (email, purpose, hash_otp(otp), user_name, OTP_EXPIRY_MINUTES, get_client_ip()),
    )
    session["pending_otp"] = {"email": email, "purpose": purpose, "name": user_name}
    return True, "We sent a 6-digit OTP to your email."


def verify_otp_challenge(email: str, purpose: str, otp: str) -> Tuple[bool, str]:
    if not re.fullmatch(r"\d{6}", otp or ""):
        return False, "Enter the 6-digit OTP sent to your email."

    challenge = latest_pending_otp(email, purpose)
    if not challenge:
        return False, "This OTP is invalid or has expired. Please request a new code."

    if int(challenge.get("attempts") or 0) >= OTP_MAX_VERIFY_ATTEMPTS:
        execute_query("UPDATE email_otps SET consumed_at = UTC_TIMESTAMP() WHERE id = %s", (challenge["id"],))
        return False, "Too many incorrect attempts. Please request a new OTP."

    if not check_otp_hash(challenge["otp_hash"], otp):
        execute_query("UPDATE email_otps SET attempts = attempts + 1 WHERE id = %s", (challenge["id"],))
        return False, "The OTP you entered is incorrect."

    execute_query("UPDATE email_otps SET consumed_at = UTC_TIMESTAMP() WHERE id = %s", (challenge["id"],))
    return True, ""


def ensure_user_account(name: str, email: str, password_hash: Optional[str] = None) -> int:
    existing_user = query_user_by_email(email)
    if existing_user:
        return int(existing_user["id"])

    user_id = execute_query(
        """
        INSERT INTO users (name, email, password_hash, role)
        VALUES (%s, %s, %s, %s)
        """,
        (
            name or email.split("@")[0],
            email,
            password_hash or generate_password_hash(secrets.token_urlsafe(24)),
            "user",
        ),
        return_lastrowid=True,
    )
    execute_query(
        """
        INSERT INTO profiles (user_id, phone, location, career_interests, linkedin, profile_picture_url)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (user_id, "", "", "", "", ""),
    )
    return int(user_id)


def clear_auth_sessions() -> None:
    session.pop("pending_otp", None)
    session.pop("pending_registration", None)
    session.pop("pending_password_reset", None)


def otp_verify_heading(purpose: str) -> Tuple[str, str]:
    if purpose == "register":
        return "Verify Your Email", "Enter the 6-digit code sent to"
    if purpose == "reset_password":
        return "Reset Password OTP", "Enter the 6-digit code sent to"
    return "Login With OTP", "Enter the 6-digit code sent to"


def build_user_initials(name: str) -> str:
    parts = [part.strip() for part in str(name or "").split() if part.strip()]
    if not parts:
        return "CL"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return f"{parts[0][0]}{parts[-1][0]}".upper()


def load_trusted_users(limit: int = 3) -> List[Dict[str, Any]]:
    users = fetch_all(
        """
        SELECT u.name, p.profile_image, p.profile_picture_url
        FROM users u
        LEFT JOIN profiles p ON p.user_id = u.id
        WHERE u.role = %s
        ORDER BY u.created_at DESC, u.id DESC
        LIMIT %s
        """,
        ("user", limit),
    )
    return [
        {
            "name": user["name"],
            "profile_picture_url": resolve_profile_image_url(user),
            "initials": build_user_initials(user["name"]),
        }
        for user in users
    ]


def load_trusted_user_count() -> int:
    record = fetch_one("SELECT COUNT(*) AS count FROM users WHERE role = %s", ("user",))
    return int(record["count"]) if record else 0


def fetch_recent_resume_summaries(limit: int = 5) -> List[Dict[str, Any]]:
    return fetch_all(
        """
        SELECT r.filename, r.uploaded_at, u.name, u.email
        FROM resumes r
        INNER JOIN users u ON u.id = r.user_id
        ORDER BY r.uploaded_at DESC, r.id DESC
        LIMIT %s
        """,
        (limit,),
    )


def current_user() -> Optional[Dict[str, Any]]:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return query_user_by_id(int(user_id))


def validate_password_strength(password: str) -> Optional[str]:
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include at least one special character."
    return None


def login_required(role: Optional[str] = None):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            user = current_user()
            if user is None:
                flash("Please log in to continue.", "warning")
                target = "admin_login" if role == "admin" else "user_login"
                return redirect(url_for(target))
            if role and user["role"] != role:
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("index"))
            return view(*args, **kwargs)

        return wrapped_view

    return decorator


@app.context_processor
def inject_user() -> Dict[str, Any]:
    user = current_user()
    profile = query_profile_by_user_id(int(user["id"])) if user else None
    return {
        "current_user": user,
        "current_user_profile": profile or {},
        "current_user_profile_image": resolve_profile_image_url(profile),
        "current_user_initials": build_user_initials(user["name"]) if user else "",
    }


def filter_jobs_by_location(dataframe: pd.DataFrame, location: str) -> pd.DataFrame:
    if not location:
        return dataframe
    return dataframe[
        dataframe["location"].astype(str).str.contains(location, case=False, na=False)
    ]


def normalize_skill_terms(skills_text: str) -> List[str]:
    return [skill.strip().lower() for skill in str(skills_text).split(",") if skill.strip()]


def build_job_card(row: pd.Series, match_score: float, model_used: str) -> Dict[str, Any]:
    return {
        "id": row.get("id"),
        "title": row.get("title", "N/A"),
        "company": row.get("company", "N/A"),
        "location": row.get("location", "N/A"),
        "skills": row.get("skills", ""),
        "platform": row.get("platform", "N/A"),
        "link": row.get("link", "#"),
        "match_score": int(match_score),
        "model_used": model_used,
    }


def ml_match_jobs(dataframe: pd.DataFrame, user_skills: str, location: str) -> List[Dict[str, Any]]:
    normalized_location = location.strip()
    user_skill_set = set(normalize_skill_terms(user_skills))

    if dataframe.empty or not normalized_location or not user_skill_set:
        return []

    filtered_jobs = filter_jobs_by_location(dataframe, normalized_location)
    if filtered_jobs.empty:
        return []

    results: List[Dict[str, Any]] = []

    for _, row in filtered_jobs.iterrows():
        job_skill_set = set(normalize_skill_terms(row.get("skills", "")))
        matched_skills = sorted(user_skill_set.intersection(job_skill_set))
        if not matched_skills:
            continue

        title_text = str(row.get("title", "")).lower()
        title_skill_hits = sum(1 for skill in matched_skills if skill in title_text)
        location_exact = str(row.get("location", "")).strip().lower() == normalized_location.lower()
        skill_coverage = len(matched_skills) / max(len(user_skill_set), 1)
        ranking_score = (
            len(matched_skills) * 100
            + title_skill_hits * 20
            + (15 if location_exact else 0)
            + skill_coverage
        )

        job_card = build_job_card(row, int(skill_coverage * 100), "Skills and location match")
        job_card["matched_skills"] = [skill.title() for skill in matched_skills]
        job_card["skill_match_count"] = len(matched_skills)
        job_card["ranking_score"] = ranking_score
        results.append(job_card)

    results.sort(key=lambda job: (job["skill_match_count"], job["ranking_score"]), reverse=True)
    return results


def build_dashboard_data(dataframe: pd.DataFrame) -> Dict[str, Any]:
    skill_counts: Dict[str, int] = {}
    for skill_list in dataframe.get("skills", pd.Series(dtype=str)).fillna(""):
        for skill in [item.strip() for item in str(skill_list).split(",") if item.strip()]:
            skill_counts[skill] = skill_counts.get(skill, 0) + 1

    location_counts = dataframe["location"].value_counts().to_dict() if "location" in dataframe else {}
    company_counts = dataframe["company"].value_counts().head(5).to_dict() if "company" in dataframe else {}
    top_skills = sorted(skill_counts.items(), key=lambda item: item[1], reverse=True)[:6]

    return {
        "skills_labels": [item[0] for item in top_skills],
        "skills_values": [item[1] for item in top_skills],
        "location_labels": list(location_counts.keys()),
        "location_values": list(location_counts.values()),
        "company_labels": list(company_counts.keys()),
        "company_values": list(company_counts.values()),
        "total_jobs": int(len(dataframe.index)),
        "total_locations": int(len(location_counts)),
        "total_companies": int(dataframe["company"].nunique()) if "company" in dataframe else 0,
    }


def build_dashboard_data_from_database() -> Dict[str, Any]:
    skills_rows = fetch_all(
        """
        SELECT skills
        FROM jobs
        WHERE COALESCE(skills, '') <> ''
        """
    )
    skill_counts: Counter[str] = Counter()
    for row in skills_rows:
        for skill in [item.strip() for item in str(row.get("skills", "")).split(",") if item.strip()]:
            skill_counts[skill] += 1

    top_skills = skill_counts.most_common(6)
    top_locations = fetch_all(
        """
        SELECT location, COUNT(*) AS total
        FROM jobs
        WHERE COALESCE(location, '') <> ''
        GROUP BY location
        ORDER BY total DESC
        LIMIT 8
        """
    )
    top_companies = fetch_all(
        """
        SELECT company, COUNT(*) AS total
        FROM jobs
        WHERE COALESCE(company, '') <> ''
        GROUP BY company
        ORDER BY total DESC
        LIMIT 5
        """
    )

    return {
        "skills_labels": [item[0] for item in top_skills],
        "skills_values": [item[1] for item in top_skills],
        "location_labels": [row["location"] for row in top_locations],
        "location_values": [int(row["total"]) for row in top_locations],
        "company_labels": [row["company"] for row in top_companies],
        "company_values": [int(row["total"]) for row in top_companies],
        "total_jobs": count_jobs(),
        "total_locations": int((fetch_one("SELECT COUNT(DISTINCT location) AS count FROM jobs WHERE COALESCE(location, '') <> ''") or {}).get("count", 0)),
        "total_companies": int((fetch_one("SELECT COUNT(DISTINCT company) AS count FROM jobs WHERE COALESCE(company, '') <> ''") or {}).get("count", 0)),
    }


def build_fraud_fallback(message: str) -> Dict[str, Any]:
    return {
        "success": False,
        "error": message,
        "analysis": {
            "classification": "FAKE",
            "risk_score": 0,
            "confidence": 0,
            "scam_indicators": [],
            "company_analysis": {
                "company_present": False,
                "company_verifiable": False,
            },
            "contact_analysis": {
                "uses_free_email": False,
                "uses_messaging_apps": False,
            },
            "salary_analysis": {
                "salary_present": False,
                "salary_unrealistic": False,
            },
            "text_quality": {
                "grammar_quality": "moderate",
                "generic_description": False,
            },
            "explanation": "We could not complete the fraud analysis right now.",
            "recommended_action": "caution",
        },
    }


def clamp_percentage(value: Any) -> int:
    try:
        return max(0, min(100, int(round(float(value)))))
    except (TypeError, ValueError):
        return 0


def is_gemini_retryable_error(error: Exception) -> bool:
    message = str(error).lower()
    retryable_markers = (
        "429",
        "503",
        "unavailable",
        "high demand",
        "resource exhausted",
        "rate limit",
        "timed out",
        "timeout",
        "deadline exceeded",
        "quota",
    )
    return any(marker in message for marker in retryable_markers)


def run_gemini_request_with_retries(request_fn):
    attempts = max(1, GEMINI_MAX_RETRIES)
    last_error: Optional[Exception] = None

    for attempt in range(attempts):
        try:
            return request_fn()
        except Exception as error:
            last_error = error
            should_retry = attempt < attempts - 1 and is_gemini_retryable_error(error)
            if not should_retry:
                raise
            time.sleep(GEMINI_RETRY_BASE_DELAY_SECONDS * (2 ** attempt))

    if last_error:
        raise last_error
    raise RuntimeError("Gemini request failed without returning an error.")


def build_gemini_error_message(error: Exception, feature_name: str = "AI analysis") -> str:
    if is_gemini_retryable_error(error):
        return f"{feature_name} is temporarily busy due to high demand. Please try again in a few moments."
    return f"{feature_name} failed: {error}"


def should_fallback_to_groq(error: Exception) -> bool:
    message = str(error).lower()
    fallback_markers = (
        "429",
        "503",
        "quota",
        "resource exhausted",
        "rate limit",
        "high demand",
        "unavailable",
        "deadline exceeded",
        "timeout",
        "timed out",
        "malformed json",
    )
    return any(marker in message for marker in fallback_markers)


def is_groq_retryable_error(error: Exception) -> bool:
    message = str(error).lower()
    retryable_markers = (
        "429",
        "503",
        "rate limit",
        "quota",
        "timed out",
        "timeout",
        "temporarily unavailable",
        "overloaded",
    )
    return any(marker in message for marker in retryable_markers)


def run_groq_request_with_retries(request_fn):
    attempts = max(1, GROQ_MAX_RETRIES)
    last_error: Optional[Exception] = None

    for attempt in range(attempts):
        try:
            return request_fn()
        except Exception as error:
            last_error = error
            should_retry = attempt < attempts - 1 and is_groq_retryable_error(error)
            if not should_retry:
                raise
            time.sleep(GROQ_RETRY_BASE_DELAY_SECONDS * (2 ** attempt))

    if last_error:
        raise last_error
    raise RuntimeError("Groq request failed without returning an error.")


def compute_fraud_risk_score(
    classification: str,
    recommended_action: str,
    indicators: List[str],
    company_analysis: Dict[str, Any],
    contact_analysis: Dict[str, Any],
    salary_analysis: Dict[str, Any],
    text_quality: Dict[str, Any],
    raw_score: Any,
) -> int:
    try:
        raw_score_value = float(raw_score)
    except (TypeError, ValueError):
        raw_score_value = 0.0

    score = max(0.0, min(100.0, raw_score_value))
    score = max(score, min(len(indicators) * 12, 72))

    if classification == "FAKE":
        score = max(score, 45)
    if recommended_action == "caution":
        score = max(score, 35)
    elif recommended_action == "avoid":
        score = max(score, 65)

    if not company_analysis.get("company_present"):
        score += 8
    if not company_analysis.get("company_verifiable"):
        score += 14
    if contact_analysis.get("uses_free_email"):
        score += 10
    if contact_analysis.get("uses_messaging_apps"):
        score += 12
    if salary_analysis.get("salary_unrealistic"):
        score += 15
    if text_quality.get("generic_description"):
        score += 7

    grammar_quality = str(text_quality.get("grammar_quality", "moderate")).lower()
    if grammar_quality == "poor":
        score += 8
    elif grammar_quality == "moderate":
        score += 3

    return clamp_percentage(score)


def compute_fraud_confidence_score(
    classification: str,
    indicators: List[str],
    company_analysis: Dict[str, Any],
    contact_analysis: Dict[str, Any],
    salary_analysis: Dict[str, Any],
    text_quality: Dict[str, Any],
    raw_confidence: Any,
) -> int:
    try:
        raw_confidence_value = float(raw_confidence)
    except (TypeError, ValueError):
        raw_confidence_value = 0.0

    evidence_points = len(indicators)
    evidence_points += 0 if company_analysis.get("company_present") else 1
    evidence_points += 0 if company_analysis.get("company_verifiable") else 1
    evidence_points += 1 if contact_analysis.get("uses_free_email") else 0
    evidence_points += 1 if contact_analysis.get("uses_messaging_apps") else 0
    evidence_points += 1 if salary_analysis.get("salary_unrealistic") else 0
    evidence_points += 1 if text_quality.get("generic_description") else 0

    grammar_quality = str(text_quality.get("grammar_quality", "moderate")).lower()
    if grammar_quality == "poor":
        evidence_points += 1

    confidence = max(0.0, min(100.0, raw_confidence_value))
    confidence = max(confidence, min(35 + evidence_points * 8, 96))

    if classification == "FAKE" and evidence_points >= 3:
        confidence = max(confidence, 70)
    elif classification == "LEGITIMATE" and evidence_points == 0:
        confidence = max(confidence, 65)

    return clamp_percentage(confidence)


def normalize_fraud_analysis(data: Dict[str, Any]) -> Dict[str, Any]:
    company_analysis = data.get("company_analysis") or {}
    contact_analysis = data.get("contact_analysis") or {}
    salary_analysis = data.get("salary_analysis") or {}
    text_quality = data.get("text_quality") or {}

    classification = str(data.get("classification", "FAKE")).upper()
    if classification not in {"FAKE", "LEGITIMATE"}:
        classification = "FAKE"

    grammar_quality = str(text_quality.get("grammar_quality", "moderate")).lower()
    if grammar_quality not in {"good", "moderate", "poor"}:
        grammar_quality = "moderate"

    recommended_action = str(data.get("recommended_action", "caution")).lower()
    if recommended_action not in {"safe", "caution", "avoid"}:
        recommended_action = "caution"

    indicators = data.get("scam_indicators")
    if not isinstance(indicators, list):
        indicators = []

    normalized_indicators = [str(item).strip() for item in indicators if str(item).strip()]
    normalized_company_analysis = {
        "company_present": bool(company_analysis.get("company_present")),
        "company_verifiable": bool(company_analysis.get("company_verifiable")),
    }
    normalized_contact_analysis = {
        "uses_free_email": bool(contact_analysis.get("uses_free_email")),
        "uses_messaging_apps": bool(contact_analysis.get("uses_messaging_apps")),
    }
    normalized_salary_analysis = {
        "salary_present": bool(salary_analysis.get("salary_present")),
        "salary_unrealistic": bool(salary_analysis.get("salary_unrealistic")),
    }
    normalized_text_quality = {
        "grammar_quality": grammar_quality,
        "generic_description": bool(text_quality.get("generic_description")),
    }

    return {
        "classification": classification,
        "risk_score": compute_fraud_risk_score(
            classification,
            recommended_action,
            normalized_indicators,
            normalized_company_analysis,
            normalized_contact_analysis,
            normalized_salary_analysis,
            normalized_text_quality,
            data.get("risk_score"),
        ),
        "confidence": compute_fraud_confidence_score(
            classification,
            normalized_indicators,
            normalized_company_analysis,
            normalized_contact_analysis,
            normalized_salary_analysis,
            normalized_text_quality,
            data.get("confidence"),
        ),
        "scam_indicators": normalized_indicators,
        "company_analysis": normalized_company_analysis,
        "contact_analysis": normalized_contact_analysis,
        "salary_analysis": normalized_salary_analysis,
        "text_quality": normalized_text_quality,
        "explanation": str(data.get("explanation", "")).strip() or "No explanation was returned.",
        "recommended_action": recommended_action,
    }


def analyze_job_with_gemini(job_text: str) -> Dict[str, Any]:
    reduced_job_text = reduce_text_for_llm(job_text, "Job posting")
    prompt = (
        "You are an expert in online recruitment fraud detection.\n\n"
        "Analyze the job posting carefully and determine whether it is legitimate or fraudulent.\n\n"
        "Important rules:\n"
        "- Do not invent red flags, weaknesses, or errors.\n"
        "- If the posting looks genuinely legitimate, return a high-confidence LEGITIMATE result with a low risk score.\n"
        "- If the posting is suspicious, score it accurately using only evidence from the text.\n"
        "- Base the result only on the provided content.\n\n"
        "Evaluate using these criteria:\n"
        "- unrealistic salary\n"
        "- requests for upfront payments\n"
        "- suspicious contact methods (WhatsApp, Telegram)\n"
        "- missing company information\n"
        "- vague description\n"
        "- urgency tactics\n"
        "- unrealistic work-from-home income\n"
        "- poor grammar\n"
        "- crypto or gift card payments\n"
        "- free email domains (gmail, yahoo, outlook)\n\n"
        "Return ONLY valid JSON that matches the required schema.\n\n"
        f"Reduced job posting context:\n{reduced_job_text[:MAX_REDUCED_TEXT_CHARS]}"
    )

    errors: List[str] = []

    if GEMINI_AVAILABLE and GEMINI_API_KEY:
        try:
            def request_fraud_analysis():
                if genai and gemini_client:
                    return gemini_client.models.generate_content(
                        model=GEMINI_FRAUD_MODEL,
                        contents=prompt,
                        config={
                            "response_mime_type": "application/json",
                            "response_json_schema": FRAUD_ANALYSIS_SCHEMA["schema"],
                        },
                    )
                if google_generativeai:
                    google_generativeai.configure(api_key=GEMINI_API_KEY)
                    model = google_generativeai.GenerativeModel(GEMINI_FRAUD_MODEL)
                    return model.generate_content(prompt)
                raise RuntimeError("Gemini SDK is not installed on the server.")

            response = run_gemini_request_with_retries(
                request_fraud_analysis
            )
            response_text = getattr(response, "text", "") or ""
            parsed = parse_json_object(response_text)
            return {
                "success": True,
                "error": None,
                "analysis": normalize_fraud_analysis(parsed),
            }
        except json.JSONDecodeError as error:
            errors.append("Gemini returned malformed JSON.")
            if not groq_client:
                return build_fraud_fallback("The model returned malformed JSON. Please try again.")
        except Exception as error:
            errors.append(build_gemini_error_message(error, "Fraud analysis"))
            if not groq_client or not should_fallback_to_groq(error):
                return build_fraud_fallback(build_gemini_error_message(error, "Fraud analysis"))
    elif not groq_client:
        return build_fraud_fallback("No AI provider is configured. Add Gemini or Groq credentials in the .env file.")

    if GROQ_AVAILABLE and GROQ_API_KEY and groq_client:
        groq_models = parse_model_priority_list(
            GROQ_FRAUD_MODEL,
            ["openai/gpt-oss-120b", "qwen/qwen3-32b", "openai/gpt-oss-20b"],
        )
        groq_schema_instructions = json.dumps(FRAUD_ANALYSIS_SCHEMA["schema"], ensure_ascii=True)
        groq_messages = [
            {
                "role": "system",
                "content": (
                    "You are an expert in online recruitment fraud detection. "
                    "Do not invent issues. If the job description is genuinely strong and trustworthy, score it accordingly. "
                    "If it is suspicious, return an evidence-based result. "
                    f"Return ONLY valid JSON that matches this schema: {groq_schema_instructions}"
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ]
        for groq_model in groq_models:
            try:
                response = run_groq_request_with_retries(
                    lambda groq_model=groq_model: groq_client.chat.completions.create(
                        model=groq_model,
                        temperature=0.2,
                        messages=groq_messages,
                        response_format={"type": "json_object"},
                    )
                )
                raw_text = response.choices[0].message.content or "{}"
                parsed = parse_json_object(raw_text)
                return {
                    "success": True,
                    "error": None,
                    "analysis": normalize_fraud_analysis(parsed),
                }
            except json.JSONDecodeError:
                errors.append(f"Groq fraud analysis malformed JSON from {groq_model}.")
            except Exception as error:
                errors.append(f"Groq fraud analysis failed on {groq_model}: {error}")

    message = errors[-1] if errors else "Fraud analysis is temporarily unavailable."
    return build_fraud_fallback(message)


def extract_resume_text(file_path: Path) -> str:
    text = ""
    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text += f"{page_text}\n"
    return text.strip()


def extract_skills(text: str) -> List[str]:
    text_lower = text.lower()
    return [skill for skill in COMMON_SKILLS if skill in text_lower]


def recommend_roles_from_jobs(resume_skills: List[str], jobs_df: pd.DataFrame) -> List[str]:
    role_scores: Dict[str, int] = {}
    resume_skill_set = {skill.lower().strip() for skill in resume_skills}

    for _, row in jobs_df.iterrows():
        job_skills = str(row["skills"]).lower().split(",")
        job_skill_set = {skill.strip() for skill in job_skills}
        matches = resume_skill_set.intersection(job_skill_set)

        if matches:
            role = str(row["title"])
            role_scores[role] = role_scores.get(role, 0) + len(matches)

    sorted_roles = sorted(role_scores.items(), key=lambda item: item[1], reverse=True)
    return [role for role, _ in sorted_roles[:3]]


def analyze_resume_text(text: str) -> str:
    skills = extract_skills(text)
    text_lower = text.lower()
    score = min(100, 50 + len(skills) * 5)

    sections = {
        "Education": "education" in text_lower,
        "Experience": "experience" in text_lower or "work experience" in text_lower,
        "Projects": "project" in text_lower,
        "Skills": "skills" in text_lower,
        "Certifications": "certification" in text_lower,
        "Summary": "summary" in text_lower or "profile" in text_lower,
    }

    suggestions: List[str] = []
    if not sections["Projects"]:
        suggestions.append("Add project experience")
    if not sections["Certifications"]:
        suggestions.append("Include certifications")
    if "github" not in text_lower:
        suggestions.append("Add GitHub or portfolio link")
    if len(skills) < 4:
        suggestions.append("Add more technical skills")

    strengths: List[str] = []
    if len(skills) >= 5:
        strengths.append("Strong technical skillset")
    if sections["Projects"]:
        strengths.append("Projects included")
    if sections["Experience"]:
        strengths.append("Work experience present")

    recommended_roles = recommend_roles_from_jobs(skills, load_jobs())
    role = ", ".join(recommended_roles) if recommended_roles else "General"

    return f"""
<h5>Resume Score: {score}/100</h5>

<h6>Suggested Roles</h6>
<p>{role}</p>

<h6>Detected Skills</h6>
<p>{', '.join(skills) if skills else 'No major skills detected'}</p>

<h6>Resume Sections Found</h6>
<ul>
{''.join([f"<li>{section}</li>" for section, exists in sections.items() if exists])}
</ul>

<h6>Strengths</h6>
<ul>
{''.join([f"<li>{item}</li>" for item in strengths])}
</ul>

<h6>Suggestions for Improvement</h6>
<ul>
{''.join([f"<li>{item}</li>" for item in suggestions])}
</ul>
"""


def top_market_skills(limit: int = 8) -> List[str]:
    jobs_df = load_jobs()
    if jobs_df.empty or "skills" not in jobs_df:
        return []

    skill_counter: Counter[str] = Counter()
    for skills_text in jobs_df["skills"].fillna(""):
        skills = [skill.strip() for skill in str(skills_text).split(",") if skill.strip()]
        skill_counter.update(skill.lower() for skill in skills)

    return [skill.title() for skill, _ in skill_counter.most_common(limit)]


def parse_json_object(raw_text: str) -> Dict[str, Any]:
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


def clean_string_list(values: Any, fallback: Optional[List[str]] = None) -> List[str]:
    fallback = fallback or []
    if not isinstance(values, list):
        return fallback

    cleaned: List[str] = []
    for value in values:
        item = str(value).strip()
        if item and item not in cleaned:
            cleaned.append(item)
    return cleaned


def build_resume_fallback(message: str, extracted_text: str = "") -> Dict[str, Any]:
    detected_skills = extract_skills(extracted_text) if extracted_text else []
    market_skills = top_market_skills()
    fallback_skills = detected_skills[:4] or market_skills[:4]

    return {
        "success": False,
        "error": message,
        "analysis": {
            "resume_score": 0,
            "summary": "We could not complete the AI resume review right now.",
            "strengths": ["Resume file uploaded successfully."] if extracted_text else [],
            "weaknesses": ["AI analysis is temporarily unavailable."],
            "missing_sections": [],
            "improvement_tips": [
                "Try uploading a clearer text-based PDF resume.",
                "Check that the Gemini and Groq API settings are configured correctly in the .env file.",
            ],
            "suggested_skills": fallback_skills,
        },
    }


def normalize_resume_analysis(data: Dict[str, Any], extracted_text: str = "") -> Dict[str, Any]:
    market_skills = top_market_skills()
    extracted_skills = [skill.title() for skill in extract_skills(extracted_text)]

    summary = str(data.get("summary", "")).strip() or "No summary was returned."
    score_raw = data.get("resume_score", 0)
    try:
        score = int(round(float(score_raw)))
    except (TypeError, ValueError):
        score = 0

    suggested_skills = clean_string_list(data.get("suggested_skills"))
    if not suggested_skills:
        suggested_skills = extracted_skills[:3] + [skill for skill in market_skills if skill not in extracted_skills]

    return {
        "resume_score": max(0, min(100, score)),
        "summary": summary,
        "strengths": clean_string_list(data.get("strengths")),
        "weaknesses": clean_string_list(data.get("weaknesses")),
        "missing_sections": clean_string_list(data.get("missing_sections")),
        "improvement_tips": clean_string_list(data.get("improvement_tips")),
        "suggested_skills": suggested_skills[:8],
    }


def analyze_resume_with_gemini(resume_text: str) -> Dict[str, Any]:
    if not resume_text.strip():
        return build_resume_fallback("No readable text was found in the uploaded PDF.")

    reduced_resume_text = reduce_text_for_llm(resume_text, "Resume")
    prompt = (
        "You are an expert resume reviewer and career advisor.\n\n"
        "Analyze the resume text and provide structured feedback.\n\n"
        "Important rules:\n"
        "- Do not invent errors or weaknesses.\n"
        "- If the resume is genuinely strong, reward it with a strong score and concise positive feedback.\n"
        "- If the resume is weak or incomplete, score it accurately using only evidence from the text.\n"
        "- Keep every point grounded in the provided resume content.\n\n"
        "Evaluate:\n"
        "- overall resume quality\n"
        "- skills relevance\n"
        "- formatting clarity\n"
        "- experience strength\n"
        "- missing important sections\n"
        "- improvement suggestions\n\n"
        "Return ONLY valid JSON.\n\n"
        "Schema:\n"
        "{\n"
        '  "resume_score": number,\n'
        '  "summary": "",\n'
        '  "strengths": [],\n'
        '  "weaknesses": [],\n'
        '  "missing_sections": [],\n'
        '  "improvement_tips": [],\n'
        '  "suggested_skills": []\n'
        "}\n\n"
        f"Current market skills to keep in mind: {', '.join(top_market_skills()) or 'Not available'}\n\n"
        f"Reduced resume context:\n{reduced_resume_text[:MAX_REDUCED_TEXT_CHARS]}"
    )

    errors: List[str] = []

    if GEMINI_AVAILABLE and GEMINI_API_KEY:
        try:
            def request_resume_analysis():
                if google_generativeai:
                    google_generativeai.configure(api_key=GEMINI_API_KEY)
                    model = google_generativeai.GenerativeModel(GEMINI_RESUME_MODEL)
                    return model.generate_content(prompt)
                if genai:
                    client = genai.Client(api_key=GEMINI_API_KEY)
                    return client.models.generate_content(model=GEMINI_RESUME_MODEL, contents=prompt)
                raise RuntimeError("Gemini SDK is not installed on the server.")

            response = run_gemini_request_with_retries(request_resume_analysis)
            raw_text = getattr(response, "text", "") or ""
            parsed = parse_json_object(raw_text)
            return {
                "success": True,
                "error": None,
                "analysis": normalize_resume_analysis(parsed, resume_text),
            }
        except json.JSONDecodeError:
            errors.append("Gemini returned malformed JSON.")
            if not groq_client:
                return build_resume_fallback("The model returned malformed JSON. Please try again.", resume_text)
        except Exception as error:
            errors.append(build_gemini_error_message(error, "Resume analysis"))
            if not groq_client or not should_fallback_to_groq(error):
                return build_resume_fallback(build_gemini_error_message(error, "Resume analysis"), resume_text)
    elif not groq_client:
        return build_resume_fallback("No AI provider is configured. Add Gemini or Groq credentials in the .env file.", resume_text)

    if GROQ_AVAILABLE and GROQ_API_KEY and groq_client:
        groq_models = parse_model_priority_list(
            GROQ_RESUME_MODEL,
            ["openai/gpt-oss-120b", "qwen/qwen3-32b", "openai/gpt-oss-20b"],
        )
        groq_messages = [
            {
                "role": "system",
                "content": (
                    "You are an expert resume reviewer and career advisor. "
                    "Do not invent errors or weaknesses. If the resume is genuinely strong, score it highly. "
                    "If it is weak, score it accurately using only evidence from the text. "
                    "Return ONLY valid JSON with keys: resume_score, summary, strengths, weaknesses, missing_sections, improvement_tips, suggested_skills."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ]
        for groq_model in groq_models:
            try:
                response = run_groq_request_with_retries(
                    lambda groq_model=groq_model: groq_client.chat.completions.create(
                        model=groq_model,
                        temperature=0.2,
                        messages=groq_messages,
                        response_format={"type": "json_object"},
                    )
                )
                raw_text = response.choices[0].message.content or "{}"
                parsed = parse_json_object(raw_text)
                return {
                    "success": True,
                    "error": None,
                    "analysis": normalize_resume_analysis(parsed, resume_text),
                }
            except json.JSONDecodeError:
                errors.append(f"Groq resume analysis malformed JSON from {groq_model}.")
            except Exception as error:
                errors.append(f"Groq resume analysis failed on {groq_model}: {error}")

    message = errors[-1] if errors else "Resume analysis is temporarily unavailable."
    return build_resume_fallback(message, resume_text)


def generate_support_reply(message: str) -> str:
    text = message.strip()
    if not text:
        return "Please type your question and I will help you use CareerLink's job recommendations, resume analyzer, fraud detection, and market insights."

    if not GROQ_API_KEY or not groq_client:
        return "CareerLink assistant is temporarily unavailable because the Groq API settings are missing. Please try again shortly."

    try:
        reduced_text = reduce_text_for_llm(text, "User question", max_chars=MAX_CHAT_TEXT_CHARS)
        prompt = f"{CAREERLINK_SUPPORT_PROMPT}\n\nReduced user question:\n{reduced_text}"

        response = run_groq_request_with_retries(
            lambda: groq_client.chat.completions.create(
                model=GROQ_CHAT_MODEL,
                temperature=0.3,
                messages=[
                    {
                        "role": "system",
                        "content": "You are the CareerLink support assistant. Follow the provided instructions exactly and respond in plain text only.",
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
            )
        )
        reply = str(response.choices[0].message.content or "").strip()

        return reply or "I can help you use CareerLink features like Jobs, Resume Analyzer, Fraud Detection, and Market Insights."
    except Exception as error:
        if is_groq_retryable_error(error):
            return "CareerLink assistant is temporarily busy due to high demand. Please try again in a few moments."
        return "CareerLink assistant is temporarily unavailable right now. Please try again in a moment."


@app.route("/")
def index():
    featured_jobs = [build_job_card(pd.Series(row), 0, "Preview") for row in fetch_featured_jobs(3)]
    trusted_users = load_trusted_users(3)
    trusted_user_count = load_trusted_user_count()
    dashboard_snapshot = build_dashboard_data_from_database()
    return render_template(
        "index.html",
        featured_jobs=featured_jobs,
        trusted_users=trusted_users,
        trusted_user_count=trusted_user_count,
        dashboard_snapshot=dashboard_snapshot,
    )


@app.route("/login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "")
        user = query_user_by_email(email)

        if not is_valid_email(email):
            flash("Please enter a valid email address.", "warning")
        elif not password:
            flash("Please enter your password.", "warning")
        elif not user or user["role"] != "user":
            flash("No user account was found for this email. Please create an account first.", "warning")
        elif not check_password_hash(user["password_hash"], password):
            flash("Invalid login credentials.", "danger")
        else:
            session.clear()
            session.permanent = True
            session["user_id"] = int(user["id"])
            flash("Login successful.", "success")
            return redirect(url_for("jobs"))

    return render_template(
        "login.html",
        login_title="User Login",
        role="user",
        otp_pending=False,
        auth_mode="password",
    )


@app.route("/login/otp", methods=["GET", "POST"])
def otp_login():
    if request.method == "POST":
        email = normalize_email(request.form.get("email", ""))
        user = query_user_by_email(email)

        if not is_valid_email(email):
            flash("Please enter a valid email address.", "warning")
        elif not user or user["role"] != "user":
            flash("No user account was found for this email. Please create an account first.", "warning")
        else:
            try:
                success, message = create_otp_challenge(email, "login", str(user.get("name") or ""))
            except Exception as error:
                flash(str(error), "danger")
            else:
                flash(message, "success" if success else "warning")
                if success:
                    return redirect(url_for("verify_otp"))

    return render_template(
        "login.html",
        login_title="Login With OTP",
        role="user",
        otp_pending=False,
        auth_mode="otp_login",
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        password_error = validate_password_strength(password)
        name = " ".join(part for part in [first_name, last_name] if part).strip()

        if not first_name or not last_name or not email or not password or not confirm_password:
            flash("All fields are required.", "warning")
        elif not is_valid_email(email):
            flash("Please enter a valid email address.", "warning")
        elif password != confirm_password:
            flash("Password and confirm password must match.", "warning")
        elif password_error:
            flash(password_error, "warning")
        elif query_user_by_email(email):
            flash("An account with this email already exists.", "warning")
        else:
            try:
                success, message = create_otp_challenge(email, "register", name)
            except Exception as error:
                flash(str(error), "danger")
            else:
                flash(message, "success" if success else "warning")
                if success:
                    session["pending_registration"] = {
                        "first_name": first_name,
                        "last_name": last_name,
                        "name": name,
                        "email": email,
                        "password_hash": generate_password_hash(password),
                    }
                    return redirect(url_for("verify_otp"))

    return render_template("register.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = normalize_email(request.form.get("email", ""))
        user = query_user_by_email(email)

        if not is_valid_email(email):
            flash("Please enter a valid email address.", "warning")
        elif not user or user["role"] != "user":
            flash("No user account was found for this email.", "warning")
        else:
            try:
                success, message = create_otp_challenge(email, "reset_password", str(user.get("name") or ""))
            except Exception as error:
                flash(str(error), "danger")
            else:
                flash(message, "success" if success else "warning")
                if success:
                    session["pending_password_reset"] = {"email": email}
                    return redirect(url_for("verify_otp"))

    return render_template(
        "login.html",
        login_title="Forgot Password",
        role="user",
        otp_pending=False,
        auth_mode="forgot_password",
    )


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    pending_otp = session.get("pending_otp") or {}
    pending_registration = session.get("pending_registration") or {}
    pending_password_reset = session.get("pending_password_reset") or {}
    email = normalize_email(pending_otp.get("email", ""))
    purpose = str(pending_otp.get("purpose", ""))
    name = str(pending_otp.get("name", "")).strip()
    verify_title, verify_intro = otp_verify_heading(purpose)

    if purpose not in {"login", "register", "reset_password"} or not is_valid_email(email):
        flash("Please request a fresh OTP to continue.", "warning")
        return redirect(url_for("user_login"))
    if purpose == "register" and (
        normalize_email(pending_registration.get("email", "")) != email
        or not str(pending_registration.get("password_hash", "")).strip()
    ):
        flash("Your registration session expired. Please sign up again.", "warning")
        clear_auth_sessions()
        return redirect(url_for("register"))
    if purpose == "reset_password" and normalize_email(pending_password_reset.get("email", "")) != email:
        flash("Your password reset session expired. Please try again.", "warning")
        clear_auth_sessions()
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        success, message = verify_otp_challenge(email, purpose, otp)
        if not success:
            flash(message, "danger")
        else:
            if purpose == "register":
                registration_name = str(pending_registration.get("name", "")).strip() or name
                password_hash = str(pending_registration.get("password_hash", "")).strip()
                user_id = ensure_user_account(registration_name, email, password_hash=password_hash)
                session.clear()
                session.permanent = True
                session["user_id"] = user_id
                flash("Your account has been created successfully.", "success")
                return redirect(url_for("jobs"))

            if purpose == "reset_password":
                session["verified_password_reset_email"] = email
                session.pop("pending_otp", None)
                flash("OTP verified. Set your new password.", "success")
                return redirect(url_for("reset_password"))

            verified_user = query_user_by_email(email)
            if not verified_user or verified_user["role"] != "user":
                flash("We could not find this user account. Please try again.", "danger")
                clear_auth_sessions()
                return redirect(url_for("user_login"))

            session.clear()
            session.permanent = True
            session["user_id"] = int(verified_user["id"])
            flash("Login successful.", "success")
            return redirect(url_for("jobs"))

    return render_template(
        "login.html",
        login_title=verify_title,
        role="user",
        otp_pending=True,
        pending_email=email,
        auth_mode="otp_verify",
        otp_intro=verify_intro,
        otp_purpose=purpose,
    )


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    pending_otp = session.get("pending_otp") or {}
    pending_registration = session.get("pending_registration") or {}
    pending_password_reset = session.get("pending_password_reset") or {}
    email = normalize_email(pending_otp.get("email", ""))
    purpose = str(pending_otp.get("purpose", ""))
    name = str(pending_otp.get("name", "")).strip()

    if purpose not in {"login", "register", "reset_password"} or not is_valid_email(email):
        flash("Please request a fresh OTP to continue.", "warning")
        return redirect(url_for("user_login"))
    if purpose == "register" and normalize_email(pending_registration.get("email", "")) != email:
        flash("Your registration session expired. Please sign up again.", "warning")
        clear_auth_sessions()
        return redirect(url_for("register"))
    if purpose == "reset_password" and normalize_email(pending_password_reset.get("email", "")) != email:
        flash("Your password reset session expired. Please try again.", "warning")
        clear_auth_sessions()
        return redirect(url_for("forgot_password"))

    try:
        success, message = create_otp_challenge(email, purpose, name)
    except Exception as error:
        flash(str(error), "danger")
    else:
        flash(message, "success" if success else "warning")
    return redirect(url_for("verify_otp"))


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    email = normalize_email(session.get("verified_password_reset_email", ""))
    if not is_valid_email(email):
        flash("Please verify an OTP before resetting your password.", "warning")
        return redirect(url_for("forgot_password"))

    user = query_user_by_email(email)
    if not user or user["role"] != "user":
        flash("No user account was found for this email.", "warning")
        session.pop("verified_password_reset_email", None)
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        password_error = validate_password_strength(new_password)

        if not new_password or not confirm_password:
            flash("Both password fields are required.", "warning")
        elif new_password != confirm_password:
            flash("New password and confirmation do not match.", "warning")
        elif password_error:
            flash(password_error, "warning")
        else:
            execute_query(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (generate_password_hash(new_password), int(user["id"])),
            )
            session.pop("verified_password_reset_email", None)
            session.pop("pending_password_reset", None)
            flash("Password updated successfully. Please log in.", "success")
            return redirect(url_for("user_login"))

    return render_template("change_password.html", reset_mode=True)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "")
        user = query_user_by_email(email)

        if user and user["role"] == "admin" and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = int(user["id"])
            flash("Admin login successful.", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin credentials.", "danger")

    return render_template("login.html", login_title="Admin Login", role="admin")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/jobs", methods=["GET", "POST"])
@login_required(role="user")
def jobs():
    jobs_data: List[Dict[str, Any]] = []
    searched = False
    skills = request.args.get("skills", "").strip()
    location = request.args.get("location", "").strip()
    page = request.args.get("page", default=1, type=int) or 1
    if page < 1:
        page = 1

    if request.method == "POST":
        skills = request.form.get("skills", "").strip()
        location = request.form.get("location", "").strip()
        if not skills or not location:
            flash("Please enter both skills and location to get better recommendations.", "warning")
            return redirect(url_for("jobs"))
        return redirect(url_for("jobs", skills=skills, location=location, page=1))

    total_results = 0
    total_pages = 1
    pagination_pages: List[Optional[int]] = [1]

    if skills or location:
        searched = True
        if skills and location:
            all_matches = ml_match_jobs(load_jobs(), user_skills=skills, location=location)
            total_results = len(all_matches)
            total_pages = max(1, (total_results + JOB_RESULTS_PAGE_SIZE - 1) // JOB_RESULTS_PAGE_SIZE)
            if page > total_pages:
                page = total_pages
            start_index = (page - 1) * JOB_RESULTS_PAGE_SIZE
            end_index = start_index + JOB_RESULTS_PAGE_SIZE
            jobs_data = all_matches[start_index:end_index]
            pagination_pages = build_pagination(page, total_pages)
        else:
            flash("Please enter both skills and location to get better recommendations.", "warning")

    return render_template(
        "jobs.html",
        jobs=enrich_job_cards(jobs_data),
        searched=searched,
        selected_skills=skills,
        selected_location=location,
        current_page=page,
        total_pages=total_pages,
        total_results=total_results,
        pagination_pages=pagination_pages,
        jobs_overview=build_dashboard_data_from_database(),
    )


@app.route("/resume", methods=["GET"])
@login_required(role="user")
def resume_upload():
    return render_template("resume_upload.html")


@app.route("/analyze-resume", methods=["POST"])
@login_required(role="user")
def analyze_resume():
    resume_file = request.files.get("resume")
    if not resume_file or not resume_file.filename:
        return jsonify(build_resume_fallback("Please choose a PDF resume before starting the analysis.")), 400

    filename = secure_filename(resume_file.filename)
    if not filename or not allowed_resume_file(filename):
        return jsonify(build_resume_fallback("Only PDF resumes are supported for analysis.")), 400

    upload_dir = ensure_upload_directory()
    temp_file_path: Optional[Path] = None

    try:
        temp_file_descriptor, temp_file_name = tempfile.mkstemp(suffix=".pdf", dir=upload_dir)
        os.close(temp_file_descriptor)
        temp_file_path = Path(temp_file_name)
        resume_file.save(temp_file_path)

        resume_text = extract_resume_text(temp_file_path)
        if not resume_text.strip():
            return jsonify(build_resume_fallback("We could not extract readable text from this PDF.")), 422

        execute_query(
            """
            INSERT INTO resumes (user_id, filename)
            VALUES (%s, %s)
            """,
            (int(current_user()["id"]), filename),
        )

        result = analyze_resume_with_gemini(resume_text)
        status_code = 200 if result["success"] else 503
        return jsonify(result), status_code
    except PDFSyntaxError:
        return jsonify(build_resume_fallback("The uploaded file could not be parsed as a valid PDF.")), 422
    except Exception as error:
        return jsonify(build_resume_fallback(f"Resume analysis failed: {error}")), 500
    finally:
        if temp_file_path and temp_file_path.exists():
            temp_file_path.unlink(missing_ok=True)


@app.route("/fraud")
@login_required(role="user")
def fraud_check():
    return render_template("fraud_check.html")


@app.route("/analyze-job", methods=["POST"])
@login_required(role="user")
def analyze_job():
    payload = request.get_json(silent=True) or {}
    job_text = str(payload.get("job_text", "")).strip()

    if not job_text:
        return jsonify(build_fraud_fallback("Please paste a job posting before starting the analysis.")), 400

    result = analyze_job_with_gemini(job_text)
    status_code = 200 if result["success"] else 503
    return jsonify(result), status_code


@app.route("/dashboard")
@login_required()
def dashboard():
    return render_template("dashboard.html", dashboard_data=build_dashboard_data_from_database())


@app.route("/profile", methods=["GET", "POST"])
@login_required()
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("user_login"))

    profile_data = query_profile_by_user_id(int(user["id"])) or {}

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        location = request.form.get("location", "").strip()
        career_interests = request.form.get("career_interests", "").strip()
        linkedin = request.form.get("linkedin", "").strip()
        profile_image_file = request.files.get("profile_image")
        profile_image_path = str(profile_data.get("profile_image") or "").strip()

        if not name or not email:
            flash("Name and email are required.", "warning")
        else:
            existing_user = query_user_by_email(email)
            if existing_user and int(existing_user["id"]) != int(user["id"]):
                flash("That email is already in use by another account.", "warning")
            else:
                if profile_image_file and profile_image_file.filename:
                    try:
                        profile_image_path = save_profile_image(profile_image_file)
                    except ValueError as error:
                        flash(str(error), "warning")
                        return render_template(
                            "profile.html",
                            profile_user=user,
                            profile_data=profile_data,
                            profile_image_url=resolve_profile_image_url(profile_data),
                        )

                execute_query(
                    """
                    UPDATE users
                    SET name = %s, email = %s
                    WHERE id = %s
                    """,
                    (name, email, int(user["id"])),
                )
                execute_query(
                    """
                    UPDATE profiles
                    SET phone = %s, location = %s, career_interests = %s, linkedin = %s, profile_image = %s
                    WHERE user_id = %s
                    """,
                    (phone, location, career_interests, linkedin, profile_image_path, int(user["id"])),
                )
                flash("Profile updated successfully.", "success")
                return redirect(url_for("profile"))

    user = current_user()
    profile_data = query_profile_by_user_id(int(user["id"])) or {}
    return render_template(
        "profile.html",
        profile_user=user,
        profile_data=profile_data,
        profile_image_url=resolve_profile_image_url(profile_data),
    )


@app.route("/change-password", methods=["GET", "POST"])
@login_required()
def change_password():
    user = current_user()
    if not user:
        return redirect(url_for("user_login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        password_error = validate_password_strength(new_password)

        if not check_password_hash(user["password_hash"], current_password):
            flash("Your current password is incorrect.", "danger")
        elif new_password != confirm_password:
            flash("New password and confirmation do not match.", "warning")
        elif password_error:
            flash(password_error, "warning")
        else:
            execute_query(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (generate_password_hash(new_password), int(user["id"])),
            )
            flash("Password updated successfully.", "success")
            return redirect(url_for("change_password"))

    return render_template("change_password.html")


@app.route("/support-chat", methods=["POST"])
def support_chat():
    message = ""
    if request.is_json:
        message = str((request.get_json(silent=True) or {}).get("message", ""))
    else:
        message = request.form.get("message", "")
    return jsonify({"reply": generate_support_reply(message)})


@app.route("/admin")
def admin_root():
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/dashboard")
@login_required(role="admin")
def admin_dashboard():
    stats = {
        "jobs_count": fetch_one("SELECT COUNT(*) AS count FROM jobs")["count"],
        "users_count": fetch_one("SELECT COUNT(*) AS count FROM users WHERE role = %s", ("user",))["count"],
        "resumes_count": fetch_one("SELECT COUNT(*) AS count FROM resumes")["count"],
    }
    recent_jobs = fetch_all(
        """
        SELECT id, company, title, location, platform
        FROM jobs
        ORDER BY id DESC
        LIMIT 5
        """
    )
    return render_template(
        "admin_dashboard.html",
        stats=stats,
        recent_jobs=recent_jobs,
        recent_resumes=fetch_recent_resume_summaries(5),
        dashboard_data=build_dashboard_data_from_database(),
    )


@app.route("/admin/manage-jobs", methods=["GET", "POST"])
@login_required(role="admin")
def admin_jobs():
    page = request.args.get("page", default=1, type=int) or 1
    if page < 1:
        page = 1

    if request.method == "POST":
        action = request.form.get("action", "single").strip().lower()

        if action == "bulk_upload":
            csv_file = request.files.get("jobs_csv")
            if not csv_file or not csv_file.filename:
                flash(
                    "Please choose a CSV file. Required columns: title, company, location, skills, link, platform.",
                    "warning",
                )
                return redirect(url_for("admin_jobs"))

            if not csv_file.filename.lower().endswith(".csv"):
                flash("Only CSV files are supported for bulk job uploads.", "warning")
                return redirect(url_for("admin_jobs"))

            try:
                jobs_to_insert = parse_job_csv(csv_file)
                execute_many(
                    """
                    INSERT INTO jobs (title, company, location, skills, link, platform)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            job["title"],
                            job["company"],
                            job["location"],
                            job["skills"],
                            job["link"],
                            job["platform"],
                        )
                        for job in jobs_to_insert
                    ],
                )
                flash(
                    f"{len(jobs_to_insert)} job listing(s) uploaded successfully from CSV.",
                    "success",
                )
                return redirect(url_for("admin_jobs", page=page))
            except ValueError as error:
                flash(str(error), "warning")
                return redirect(url_for("admin_jobs", page=page))
            except MySQLDataError:
                flash(
                    "Some CSV values are too long for the database. Please check title, company, location, and platform columns.",
                    "warning",
                )
                return redirect(url_for("admin_jobs", page=page))
            except Exception:
                flash(
                    "CSV upload failed on the server. Please try a smaller file once, and if it keeps happening check the deployed logs.",
                    "danger",
                )
                return redirect(url_for("admin_jobs", page=page))

        title = request.form.get("title", "").strip()
        company = request.form.get("company", "").strip()
        location = request.form.get("location", "").strip()
        skills = request.form.get("skills", "").strip()
        link = request.form.get("link", "").strip()
        platform = request.form.get("platform", "").strip()

        if all([title, company, location, skills, link, platform]):
            try:
                validate_job_payload(
                    {
                        "title": title,
                        "company": company,
                        "location": location,
                        "skills": skills,
                        "link": link,
                        "platform": platform,
                    }
                )
                execute_query(
                    """
                    INSERT INTO jobs (title, company, location, skills, link, platform)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (title, company, location, skills, link, platform),
                )
                flash("Job added successfully.", "success")
                return redirect(url_for("admin_jobs", page=page))
            except ValueError as error:
                flash(str(error), "warning")
                return redirect(url_for("admin_jobs", page=page))
            except MySQLDataError:
                flash("One or more job fields are too long for the database. Please shorten the values and try again.", "warning")
                return redirect(url_for("admin_jobs", page=page))

        flash("Please complete all job fields.", "warning")

    total_jobs = count_jobs()
    total_pages = max(1, (total_jobs + ADMIN_JOBS_PAGE_SIZE - 1) // ADMIN_JOBS_PAGE_SIZE)
    if page > total_pages:
        page = total_pages

    jobs_list = fetch_admin_jobs_page(page, ADMIN_JOBS_PAGE_SIZE)
    return render_template(
        "admin_jobs.html",
        jobs_list=jobs_list,
        job_csv_required_columns=JOB_CSV_REQUIRED_COLUMNS,
        current_page=page,
        total_pages=total_pages,
        pagination_pages=build_pagination(page, total_pages),
        total_jobs=total_jobs,
        page_size=ADMIN_JOBS_PAGE_SIZE,
    )


@app.route("/admin/manage-jobs/edit/<int:job_id>", methods=["GET", "POST"])
@login_required(role="admin")
def edit_job(job_id: int):
    job = fetch_one(
        """
        SELECT id, title, company, location, skills, platform, link
        FROM jobs
        WHERE id = %s
        """,
        (job_id,),
    )
    if not job:
        flash("Job not found.", "warning")
        return redirect(url_for("admin_jobs"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        company = request.form.get("company", "").strip()
        location = request.form.get("location", "").strip()
        skills = request.form.get("skills", "").strip()
        link = request.form.get("link", "").strip()
        platform = request.form.get("platform", "").strip()

        if all([title, company, location, skills, link, platform]):
            execute_query(
                """
                UPDATE jobs
                SET title = %s, company = %s, location = %s, skills = %s, link = %s, platform = %s
                WHERE id = %s
                """,
                (title, company, location, skills, link, platform, job_id),
            )
            flash("Job updated successfully.", "success")
            return redirect(url_for("admin_jobs"))

        flash("Please complete all job fields.", "warning")

    return render_template("admin_job_edit.html", job=job)


@app.route("/admin/manage-jobs/delete/<int:job_id>", methods=["POST"])
@login_required(role="admin")
def delete_job(job_id: int):
    execute_query("DELETE FROM jobs WHERE id = %s", (job_id,))
    flash("Job removed successfully.", "info")
    return redirect(url_for("admin_jobs", page=request.args.get("page", default=1, type=int) or 1))


@app.route("/admin/manage-jobs/delete-selected", methods=["POST"])
@login_required(role="admin")
def delete_selected_jobs():
    selected_job_ids = request.form.getlist("selected_job_ids")
    job_ids: List[int] = []

    for raw_job_id in selected_job_ids:
        raw_value = str(raw_job_id).strip()
        if raw_value.isdigit():
            job_ids.append(int(raw_value))

    unique_job_ids = sorted(set(job_ids))
    if not unique_job_ids:
        flash("Please select at least one job to delete.", "warning")
        return redirect(url_for("admin_jobs"))

    placeholders = ", ".join(["%s"] * len(unique_job_ids))
    execute_query(f"DELETE FROM jobs WHERE id IN ({placeholders})", tuple(unique_job_ids))
    flash(f"{len(unique_job_ids)} selected job(s) removed successfully.", "info")
    return redirect(url_for("admin_jobs", page=request.form.get("page", "1")))


@app.route("/admin/manage-users")
@login_required(role="admin")
def admin_users():
    users = fetch_all(
        """
        SELECT id, name, email, role, created_at
        FROM users
        ORDER BY id DESC
        """
    )
    return render_template("admin_users.html", users=users)


@app.route("/admin/manage-users/promote/<int:user_id>", methods=["POST"])
@login_required(role="admin")
def promote_user(user_id: int):
    execute_query("UPDATE users SET role = %s WHERE id = %s", ("admin", user_id))
    flash("User promoted to admin.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/manage-users/delete/<int:user_id>", methods=["POST"])
@login_required(role="admin")
def delete_user(user_id: int):
    target_user = fetch_one("SELECT id, role FROM users WHERE id = %s", (user_id,))
    active_user = current_user()

    if not target_user:
        flash("User not found.", "warning")
        return redirect(url_for("admin_users"))
    if target_user["role"] == "admin":
        flash("Admin accounts cannot be deleted from this screen.", "danger")
        return redirect(url_for("admin_users"))
    if active_user and int(active_user["id"]) == int(user_id):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin_users"))

    execute_query("DELETE FROM resumes WHERE user_id = %s", (user_id,))
    execute_query("DELETE FROM profiles WHERE user_id = %s", (user_id,))
    execute_query("DELETE FROM users WHERE id = %s", (user_id,))
    flash("User account deleted successfully.", "info")
    return redirect(url_for("admin_users"))


@app.route("/admin/reports")
@login_required(role="admin")
def admin_reports():
    reports = {
        "jobs_by_platform": fetch_all(
            """
            SELECT platform, COUNT(*) AS total
            FROM jobs
            GROUP BY platform
            ORDER BY total DESC
            LIMIT 6
            """
        ),
        "top_locations": fetch_all(
            """
            SELECT location, COUNT(*) AS total
            FROM jobs
            GROUP BY location
            ORDER BY total DESC
            LIMIT 6
            """
        ),
        "latest_users": fetch_all(
            """
            SELECT name, email, role, created_at
            FROM users
            ORDER BY id DESC
            LIMIT 5
            """
        ),
    }
    return render_template("admin_reports.html", reports=reports)


initialize_database(generate_password_hash)


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_RUN_HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", os.getenv("FLASK_RUN_PORT", "5000"))),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )

