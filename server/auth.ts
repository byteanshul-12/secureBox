import "dotenv/config";
import Database from "better-sqlite3";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

export const db = new Database(process.env.DATABASE_PATH || "data/securebox.db");
db.pragma("journal_mode = WAL");

export const googleEnabled = Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

export const DEFAULT_RULES = [
  { id: "newsletter_rule", emailType: "newsletter", labelName: "SecureBox/Newsletter" },
  { id: "phishing_rule", emailType: "phishing", labelName: "SecureBox/PhishingThreat" },
];

export function seedDefaultRules(userId: string) {
  const insert = db.prepare(
    "INSERT OR IGNORE INTO rules (id, userId, emailType, action, labelName, active) VALUES (?, ?, ?, 'label', ?, 1)"
  );
  for (const r of DEFAULT_RULES) insert.run(`${userId}_${r.id}`, userId, r.emailType, r.labelName);
}

export const auth = betterAuth({
  database: db,
  baseURL: process.env.BETTER_AUTH_URL || process.env.APP_URL || "http://localhost:3000",
  emailAndPassword: { enabled: true, minPasswordLength: 8, autoSignIn: true },
  // Without credentials the Google button is hidden (see /api/config) and users get demo feeds
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || "unset",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "unset",
      scope: [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
      ],
      accessType: "offline",
      prompt: "select_account consent",
    },
  },
  user: {
    additionalFields: {
      protectionLevel: { type: "string", defaultValue: "balanced", input: false },
      subscription: { type: "string", defaultValue: "free", input: false },
    },
  },
  databaseHooks: {
    user: { create: { after: async (user) => seedDefaultRules(user.id) } },
  },
});

/** Creates Better Auth tables plus the app's own tables. Safe to run on every boot. */
export async function initDatabase() {
  const { runMigrations } = await getMigrations(auth.options);
  await runMigrations();

  db.exec(`
    CREATE TABLE IF NOT EXISTS emails (
      id TEXT NOT NULL,
      userId TEXT NOT NULL,
      data TEXT NOT NULL,
      scannedAt TEXT NOT NULL,
      PRIMARY KEY (userId, id)
    );
    CREATE TABLE IF NOT EXISTS rules (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      emailType TEXT NOT NULL,
      action TEXT NOT NULL,
      labelName TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS activity (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      action TEXT NOT NULL,
      type TEXT NOT NULL,
      timestamp TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS waitlist (
      email TEXT PRIMARY KEY,
      registeredAt TEXT NOT NULL
    );
  `);
}
