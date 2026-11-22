# Chitloop — real accounts, verification codes, live messaging

Node + SQLite backend that serves the Chitloop app. Sign-up sends a 6-digit code by **email** or **SMS**; accounts are only activated after the code is verified.

## Run locally
```bash
npm install
cp env.example .env      # set JWT_SECRET, then providers below
npm start                 # http://localhost:3000
```
For a quick local test with no provider, set `DEV_LOG_CODES=1` — codes print in the server console. **Never enable in production.**

## Providers
- **Email:** any SMTP service (Resend, Brevo, Mailgun, SES, Gmail app password). Fill `SMTP_*` and `MAIL_FROM` (use a verified sender domain).
- **SMS:** Twilio. Fill `TWILIO_SID`, `TWILIO_TOKEN`, `TWILIO_FROM`. Numbers must include the country code. Trial accounts only text verified numbers; some countries (e.g. India) require sender registration.

## Deploy
Needs Node 18+, HTTPS and a **persistent disk** for the SQLite file (`DB_PATH`). Works on Render, Railway, Fly.io or any VPS. Set the environment variables from `env.example` in the host's dashboard; start command `npm start`.

## What's included
Signup + code verification (10-min expiry, 5 attempts, 60 s resend limit, rate limiting), bcrypt passwords, 30-day login tokens, add contacts by email/number, real two-person messaging (polls every 3 s). The Demo account and companions still work locally.

## Gmail codes (sign-up and login)
Fill the `SMTP_*` lines in `.env` as shown in `env.example` (Gmail App Password; Gmail allows roughly 500 emails/day). Creating an account sends a code to verify the email, and every login sends a fresh code (turn off with `LOGIN_CODE=0`). Remove `DEV_LOG_CODES` once Gmail works.

## AI companions + live voice
Nexy, Sam, Ava and Leo answer chats with AI, and calling them starts a live voice conversation (speech in, spoken reply out, with a talking orb and live captions). Add `ANTHROPIC_API_KEY` to `.env` to enable it; without a key they use simple scripted replies. Speech recognition works best in Chrome/Edge; Safari support is partial, and you can always type during the call.

## Voice and video calls
Calls are real WebRTC (peer-to-peer, encrypted) between two Chitloop users: open a chat with a real contact and tap the voice or video button. They need **https** (or localhost) for microphone/camera access. For people on different networks, add a TURN server in `.env` (`TURN_URL`, `TURN_USER`, `TURN_PASS`) so calls connect behind strict firewalls. Calls to ordinary phone numbers (PSTN) are not included.

## Two-step verification (2FA)
Optional, per user: **Settings → Two-step verification**. Uses any authenticator app (TOTP, RFC 6238) with a QR code, plus 8 one-time recovery codes. Once on, login asks for the code after the password. Wrong codes lock that account for 15 minutes after 5 tries; codes can't be replayed. If a user loses both phone and recovery codes, clear their 2FA manually: `UPDATE users SET totp_on=0,totp_secret=NULL,recovery=NULL WHERE login='...';`

## Not yet included
Image/file sharing between real users, push notifications, password reset, WebSocket live delivery, and message encryption (messages are stored in plain text on your server).
