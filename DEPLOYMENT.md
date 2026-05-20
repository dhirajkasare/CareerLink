# CareerLink Deployment Notes

CareerLink is a Flask portfolio project with MySQL storage, email OTP user authentication, and optional Gemini/Groq AI features.

## Local Setup

1. Create and activate a Python 3.10 virtual environment.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` and fill in database, admin, mail, and optional AI keys.
4. Create a MySQL database user that can create and alter the configured database.
5. Start the app:

   ```bash
   python app.py
   ```

## Required Environment Variables

- `SECRET_KEY`
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM`
- `OTP_PEPPER`

## Optional Environment Variables

- `ADMIN_EMAIL`, `ADMIN_PASSWORD` for seeding an admin account
- `GOOGLE_API_KEY` or `GROQ_API_KEY` for AI features
- `SESSION_COOKIE_SECURE=true` for HTTPS deployments

## Free Deployment Shape

- App hosting: Render, Railway, Fly.io, or a similar free/student tier that supports Flask.
- Database: a free MySQL-compatible hosted database where available.
- Email: Gmail SMTP with an app password, or another free SMTP provider.

Use the included `Procfile` command for WSGI hosting:

```bash
gunicorn app:app
```

## Free-Tier Limitations

- Gmail SMTP has daily sending limits and may throttle bursts.
- Free hosting and database tiers may sleep, cold start, or pause services.
- Uploaded files on ephemeral hosts may disappear after restarts unless persistent storage is configured.
- AI API free tiers can be rate-limited or unavailable without keys.
