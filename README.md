# SecureBox AI

SecureBox is a Gmail security and inbox-intelligence app. It syncs your inbox (via Google OAuth, or simulated demo emails), scans each message with Google Gemini for phishing, spam and threat signals, and applies automation rules such as labelling, archiving or trashing.

## Features

- **Gmail scans:** AI risk scores (phishing, spam, threat), classification and a plain-language explanation for every email.
- **Automation rules:** "If classified as X, then label / archive / mark read / trash".
- **Activity trail:** audit log of scans, rule changes and settings updates.
- **Manual sandbox:** paste an email and scan it without connecting Gmail.
- **Dashboard analytics:** health index, threat timeline and category distribution.
- **Auth:** email/password sign-in via [Better Auth](https://www.better-auth.com), plus optional Google sign-in that connects Gmail.

## Tech stack

React 19, Vite 6, Tailwind CSS 4, Recharts, Motion, Express, Better Auth, SQLite (`better-sqlite3`), `@google/genai` (Gemini).

## Getting started

**Prerequisites:** Node.js 18+ and a [Gemini API key](https://aistudio.google.com/apikey) (starts with `AIza`).

```bash
npm install
cp .env.example .env   # then set GEMINI_API_KEY and BETTER_AUTH_SECRET
npm run dev
```

The app runs at http://localhost:3000. A single Express server ([server.ts](server.ts)) serves both the API and the Vite dev middleware.

## Environment variables

| Variable               | Description                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------ |
| `GEMINI_API_KEY`       | Required. Used server-side for all Gemini calls.                                     |
| `BETTER_AUTH_SECRET`   | Required. Session signing secret (`openssl rand -base64 32`).                        |
| `BETTER_AUTH_URL`      | App URL, default `http://localhost:3000`.                                            |
| `GOOGLE_CLIENT_ID`     | Optional. With the secret, enables "Continue with Google" and real Gmail scanning.   |
| `GOOGLE_CLIENT_SECRET` | Optional. Redirect URI: `http://localhost:3000/api/auth/callback/google`.            |
| `DATABASE_PATH`        | Optional. SQLite file, default `data/securebox.db` (created on first run).           |

Without Google credentials, accounts use email/password and the dashboard shows simulated demo emails.

## Scripts

| Command         | What it does                                                   |
| --------------- | -------------------------------------------------------------- |
| `npm run dev`   | Start the dev server (Express + Vite) on port 3000.            |
| `npm run build` | Build the frontend and bundle the server to `dist/server.cjs`. |
| `npm start`     | Run the production build.                                      |
| `npm run lint`  | Type-check with `tsc --noEmit`.                                |
| `npm run clean` | Remove build output.                                           |

## Project structure

```
server.ts               Express server: Better Auth, Gemini scanning, Gmail sync
server/
  auth.ts               Better Auth config and SQLite setup
  api.ts                Session-protected routes: emails, rules, activity, settings
src/
  App.tsx               Session state and page routing (landing / dashboard / sandbox)
  components/
    LandingPage.tsx     Marketing page
    AuthModal.tsx       Sign in / sign up
    Dashboard.tsx       Stats, charts, inbox, rules, activity, settings
    EmailScanner.tsx    Manual scan sandbox
  lib/auth-client.ts    Better Auth React client
  types.ts              Shared types
```

## API endpoints

| Method | Path                                   | Purpose                           |
| ------ | -------------------------------------- | --------------------------------- |
| ANY    | `/api/auth/*`                          | Better Auth (sign-up, sign-in, session, Google OAuth) |
| GET    | `/api/health`                          | Health check                      |
| GET    | `/api/emails`, `/api/activity`         | Scanned emails and audit trail    |
| GET/POST | `/api/rules`, PATCH/DELETE `/api/rules/:id` | Automation rules             |
| PATCH  | `/api/settings`                        | Protection level and plan         |
| POST   | `/api/gmail/sync`                      | Fetch and scan latest emails      |
| POST   | `/api/scan/manual`                     | Scan a pasted email               |
