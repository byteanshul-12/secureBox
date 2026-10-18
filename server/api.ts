import { Router, Request, Response, NextFunction } from "express";
import { fromNodeHeaders } from "better-auth/node";
import { auth, db, googleEnabled } from "./auth.ts";

export type SessionUser = { id: string; email: string; name: string; image?: string | null };

declare module "express-serve-static-core" {
  interface Request {
    user?: SessionUser;
  }
}

const newId = () => Math.random().toString(36).substring(2, 11);

export function logActivity(userId: string, action: string, type: "security" | "connection" | "rules" | "system") {
  try {
    db.prepare("INSERT INTO activity (id, userId, action, type, timestamp) VALUES (?, ?, ?, ?, ?)").run(
      newId(), userId, action, type, new Date().toISOString()
    );
  } catch (err) {
    console.warn("Failed to write activity log:", err);
  }
}

export async function requireUser(req: Request, res: Response, next: NextFunction) {
  const session = await auth.api.getSession({ headers: fromNodeHeaders(req.headers) });
  if (!session) return res.status(401).json({ error: "Please sign in to continue." });
  req.user = session.user as SessionUser;
  next();
}

/** Returns the user's Google access token, or null if they signed up with email/password. */
export async function getGoogleToken(req: Request): Promise<string | null> {
  try {
    const res = await auth.api.getAccessToken({
      body: { providerId: "google" },
      headers: fromNodeHeaders(req.headers),
    } as any);
    return (res as any)?.accessToken || null;
  } catch {
    return null;
  }
}

export const api = Router();

api.get("/config", (_req, res) => res.json({ googleEnabled }));

api.post("/waitlist", (req, res) => {
  const email = req.body?.email;
  if (typeof email !== "string" || !email.includes("@")) return res.status(400).json({ error: "Valid email required" });
  db.prepare("INSERT OR IGNORE INTO waitlist (email, registeredAt) VALUES (?, ?)").run(email, new Date().toISOString());
  res.json({ success: true });
});

api.use(requireUser);

api.get("/gmail/status", (req, res) => {
  const row = db.prepare("SELECT 1 FROM account WHERE userId = ? AND providerId = 'google'").get(req.user!.id);
  res.json({ connected: Boolean(row) });
});

api.get("/emails", (req, res) => {
  const rows = db.prepare("SELECT data FROM emails WHERE userId = ? ORDER BY scannedAt DESC").all(req.user!.id) as { data: string }[];
  res.json(rows.map((r) => JSON.parse(r.data)));
});

api.get("/activity", (req, res) => {
  res.json(db.prepare("SELECT * FROM activity WHERE userId = ? ORDER BY timestamp DESC LIMIT 30").all(req.user!.id));
});

const toRule = (r: any) => ({ ...r, active: Boolean(r.active) });

api.get("/rules", (req, res) => {
  res.json(db.prepare("SELECT * FROM rules WHERE userId = ?").all(req.user!.id).map(toRule));
});

api.post("/rules", (req, res) => {
  const { emailType, action, labelName } = req.body || {};
  if (!emailType || !action) return res.status(400).json({ error: "emailType and action are required" });
  const rule = {
    id: "rule_" + newId(),
    userId: req.user!.id,
    emailType,
    action,
    labelName: labelName || `SecureBox/${String(emailType).toUpperCase()}`,
    active: 1,
  };
  db.prepare("INSERT INTO rules (id, userId, emailType, action, labelName, active) VALUES (@id, @userId, @emailType, @action, @labelName, @active)").run(rule);
  logActivity(rule.userId, `Created safety rule: auto-${action} on emails classified as "${emailType}"`, "rules");
  res.json(toRule(rule));
});

api.patch("/rules/:id", (req, res) => {
  db.prepare("UPDATE rules SET active = ? WHERE id = ? AND userId = ?").run(req.body?.active ? 1 : 0, req.params.id, req.user!.id);
  res.json({ success: true });
});

api.delete("/rules/:id", (req, res) => {
  db.prepare("DELETE FROM rules WHERE id = ? AND userId = ?").run(req.params.id, req.user!.id);
  res.json({ success: true });
});

const PROTECTION = ["relaxed", "balanced", "strict", "enterprise"];
const PLANS = ["free", "superman", "batman"];

api.patch("/settings", (req, res) => {
  const { protectionLevel, subscription } = req.body || {};
  if (!PROTECTION.includes(protectionLevel) || !PLANS.includes(subscription)) {
    return res.status(400).json({ error: "Invalid settings" });
  }
  db.prepare('UPDATE "user" SET protectionLevel = ?, subscription = ? WHERE id = ?').run(protectionLevel, subscription, req.user!.id);
  logActivity(req.user!.id, `Updated settings profile: Protection set to "${protectionLevel}", Plan set to "${subscription}"`, "system");
  res.json({ success: true });
});
