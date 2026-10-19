import "dotenv/config";
import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import { toNodeHandler } from "better-auth/node";
import { auth, db, initDatabase } from "./server/auth.ts";
import { api, requireUser, getGoogleToken, logActivity } from "./server/api.ts";

const geminiError = (error: any, fallback: string) =>
  error?.status === 401 || error?.status === 403
    ? "Gemini rejected GEMINI_API_KEY. Create a key at https://aistudio.google.com/apikey and set it in .env."
    : error?.status === 429
    ? "Gemini quota exceeded (the free tier allows ~20 requests/day per model). Wait for the reset, enable billing, or set GEMINI_MODEL in .env to another model."
    : fallback;

const RISK_LEVELS = ["Safe", "Low Risk", "Medium Risk", "High Risk", "Critical"];
const CLASSIFICATIONS = ["Important", "Personal", "Work", "Newsletter", "Promotion", "Marketing", "Cold Outreach", "Spam", "Phishing", "Scam", "Suspicious"];

// Map free-form model output onto the vocabulary the dashboard and rules expect
function normalizeRisk(value: unknown, score: number): string {
  const v = String(value ?? "").toLowerCase();
  const exact = RISK_LEVELS.find((r) => r.toLowerCase() === v);
  if (exact) return exact;
  if (v.includes("crit")) return "Critical";
  if (v.includes("high")) return "High Risk";
  if (v.includes("med")) return "Medium Risk";
  if (v.includes("low")) return "Low Risk";
  if (v.includes("safe")) return "Safe";
  return score > 85 ? "Critical" : score > 65 ? "High Risk" : score > 35 ? "Medium Risk" : score > 15 ? "Low Risk" : "Safe";
}

function normalizeClass(value: unknown, riskLevel: string): string {
  const v = String(value ?? "").toLowerCase();
  const exact = CLASSIFICATIONS.find((c) => c.toLowerCase() === v);
  if (exact) return exact;
  if (/phish/.test(v)) return "Phishing";
  if (/malic|scam|fraud/.test(v)) return "Scam";
  if (/spam/.test(v)) return "Spam";
  if (/suspic/.test(v)) return "Suspicious";
  if (/news/.test(v)) return "Newsletter";
  if (/promo/.test(v)) return "Promotion";
  if (/market/.test(v)) return "Marketing";
  if (/cold|outreach/.test(v)) return "Cold Outreach";
  if (/work|job/.test(v)) return "Work";
  if (/import|urgent|transaction|legit/.test(v)) return riskLevel === "Safe" || riskLevel === "Low Risk" ? "Important" : "Suspicious";
  return "Personal";
}

// Retry transient Gemini failures (overloaded) with exponential backoff
async function generate(params: Parameters<typeof ai.models.generateContent>[0], attempts = 4) {
  for (let i = 0; ; i++) {
    try {
      return await ai.models.generateContent(params);
    } catch (err: any) {
      const transient = [500, 503, 504].includes(err?.status);
      if (!transient || i >= attempts - 1) throw err;
      await new Promise((r) => setTimeout(r, 1000 * 2 ** i));
    }
  }
}

const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-3.5-flash";
const SYNC_BATCH = 40; // new emails processed per /api/gmail/sync call; the client loops until done
const SCAN_CHUNK = 10; // emails per Gemini request

async function mapPool<T, R>(items: T[], size: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    })
  );
  return out;
}

type MailItem = { id: string; from: string; to: string; subject: string; date: string; snippet: string; bodyText: string };

/** Scans emails SCAN_CHUNK at a time and returns results keyed by email id. Emails that fail are left out so the next sync retries them. */
async function scanEmails(items: MailItem[]): Promise<Map<string, any>> {
  const chunks: MailItem[][] = [];
  for (let i = 0; i < items.length; i += SCAN_CHUNK) chunks.push(items.slice(i, i + SCAN_CHUNK));
  const results = new Map<string, any>();

  await mapPool(chunks, 3, async (chunk) => {
    const listing = chunk
      .map((m) => `### EMAIL id=${m.id}\nFrom: ${m.from}\nTo: ${m.to}\nSubject: ${m.subject}\nDate: ${m.date}\nContent:\n${(m.bodyText || m.snippet).slice(0, 1500)}`)
      .join("\n\n");
    try {
      const response = await generate({
        model: GEMINI_MODEL,
        contents: `Analyze each email below for spam, phishing, scams and malicious intent. Decide for every email whether it is spam or legitimate. Return one result per email, echoing its id exactly.\n\n${listing}`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                id: { type: Type.STRING },
                spamScore: { type: Type.INTEGER, description: "0-100" },
                phishingScore: { type: Type.INTEGER, description: "0-100" },
                threatScore: { type: Type.INTEGER, description: "0-100" },
                confidenceScore: { type: Type.INTEGER, description: "0-100" },
                riskLevel: { type: Type.STRING, enum: RISK_LEVELS },
                classification: { type: Type.STRING, enum: CLASSIFICATIONS },
                explanation: { type: Type.STRING },
                riskFactors: { type: Type.ARRAY, items: { type: Type.STRING } },
                recommendedAction: { type: Type.STRING },
              },
              required: ["id", "spamScore", "phishingScore", "threatScore", "confidenceScore", "riskLevel", "classification", "explanation", "riskFactors", "recommendedAction"],
            },
          },
        },
      });
      for (const r of JSON.parse(response.text.trim())) results.set(String(r.id), r);
    } catch (err: any) {
      if (err?.status === 401 || err?.status === 403 || err?.status === 429) throw err;
      console.warn(`Skipping ${chunk.length} emails: Gemini scan failed (${err?.status || err?.message})`);
    }
  });
  return results;
}

const app = express();
const PORT = 3000;

// Initialize Google GenAI
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      "User-Agent": "aistudio-build",
    },
  },
});

// Better Auth owns /api/auth/*; it must be mounted before express.json()
app.all("/api/auth/*", toNodeHandler(auth));

app.use(express.json());

// API health check
app.get("/api/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// Session-protected data routes (emails, rules, activity, settings)
app.use("/api", api);

/**
 * 3. URL FEATURE ANALYSIS + AI SCANNER
 */
function extractURLFeatures(rawUrl: string) {
  let parsed: URL | null = null;
  try { parsed = new URL(rawUrl.startsWith("http") ? rawUrl : `http://${rawUrl}`); } catch { /* invalid URL */ }

  const domain = parsed?.hostname || rawUrl;
  const tld = domain.split(".").slice(-1)[0] || "";
  const parts = domain.split(".");
  const subdomainCount = Math.max(0, parts.length - 2);
  const pathDepth = parsed ? parsed.pathname.split("/").filter(Boolean).length : 0;
  const hasHttps = rawUrl.startsWith("https");
  const hasIPAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
  const hasPort = Boolean(parsed?.port);
  const hasEncodedChars = /%[0-9a-fA-F]{2}/.test(rawUrl);
  const urlLength = rawUrl.length;
  const SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "account", "billing", "confirm", "suspend", "alert", "unlock", "validate", "bank", "paypal", "netflix", "amazon", "support", "token", "invoice", "prize", "claim", "free"];
  const suspiciousKeywords = SUSPICIOUS_KEYWORDS.filter(kw => rawUrl.toLowerCase().includes(kw));
  const SUSPICIOUS_TLDS = ["xyz", "info", "top", "click", "loan", "gq", "cf", "tk", "ml", "ga", "work", "online"];
  const suspiciousTLD = SUSPICIOUS_TLDS.includes(tld.toLowerCase());

  return { domain, tld, hasHttps, subdomainCount, pathDepth, hasIPAddress, hasPort, hasEncodedChars, urlLength, suspiciousKeywords, suspiciousTLD };
}

app.post("/api/scan/url", requireUser, async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== "string" || url.trim().length < 4) {
    return res.status(400).json({ error: "A valid URL is required." });
  }

  const features = extractURLFeatures(url.trim());

  const featureSummary = [
    `URL: ${url}`,
    `Domain: ${features.domain}`,
    `TLD: .${features.tld} (${features.suspiciousTLD ? "HIGH RISK TLD" : "normal TLD"})`,
    `HTTPS: ${features.hasHttps ? "Yes" : "No – HTTP only"}`,
    `Subdomains: ${features.subdomainCount}`,
    `Path depth: ${features.pathDepth}`,
    `URL length: ${features.urlLength} characters`,
    `IP address as hostname: ${features.hasIPAddress ? "YES – SUSPICIOUS" : "No"}`,
    `Custom port in URL: ${features.hasPort ? "YES – SUSPICIOUS" : "No"}`,
    `Percent-encoded characters: ${features.hasEncodedChars ? "YES – SUSPICIOUS" : "No"}`,
    `Suspicious keywords detected: ${features.suspiciousKeywords.length > 0 ? features.suspiciousKeywords.join(", ") : "None"}`,
  ].join("\n");

  try {
    const result = await generate({
      model: GEMINI_MODEL,
      contents: `Analyze this URL for phishing, malware, or social-engineering risk.\n\nEXTRACTED FEATURES:\n${featureSummary}\n\nBased on these structural features and your knowledge of malicious URL patterns, provide a detailed risk assessment.`,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            isMalicious:     { type: Type.BOOLEAN },
            riskScore:       { type: Type.INTEGER, description: "0-100 overall risk score" },
            confidenceScore: { type: Type.INTEGER, description: "0-100" },
            riskLevel:       { type: Type.STRING, enum: RISK_LEVELS },
            explanation:     { type: Type.STRING },
            riskFactors:     { type: Type.ARRAY, items: { type: Type.STRING } },
            recommendedAction: { type: Type.STRING },
          },
          required: ["isMalicious", "riskScore", "confidenceScore", "riskLevel", "explanation", "riskFactors", "recommendedAction"],
        },
      },
    });

    const parsed = JSON.parse(result.text.trim());
    parsed.riskLevel = normalizeRisk(parsed.riskLevel, parsed.riskScore ?? 0);
    res.json({
      success: true,
      result: {
        url: url.trim(),
        ...parsed,
        urlFeatures: features,
      },
    });
  } catch (error: any) {
    console.error("URL scan error:", error);
    res.status(500).json({ error: geminiError(error, "URL analysis failed. Please try again.") });
  }
});

/**
 * 4. SMS / SMISHING SCANNER
 */
app.post("/api/scan/sms", requireUser, async (req, res) => {
  const { sender, content } = req.body;
  if (!sender || !content) {
    return res.status(400).json({ error: "Sender and Content are required." });
  }

  try {
    const analysisPrompt = `Analyze this SMS message for smishing (SMS phishing), scam, spam, or social-engineering threats.\nSender: ${sender}\nSMS Content:\n${content}\n\nReturn a rigorous security risk assessment.`;

    const result = await generate({
      model: GEMINI_MODEL,
      contents: analysisPrompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            spamScore:       { type: Type.INTEGER, description: "0-100" },
            phishingScore:   { type: Type.INTEGER, description: "0-100" },
            threatScore:     { type: Type.INTEGER, description: "0-100" },
            confidenceScore: { type: Type.INTEGER, description: "0-100" },
            riskLevel:       { type: Type.STRING, enum: RISK_LEVELS },
            classification:  { type: Type.STRING, enum: CLASSIFICATIONS },
            explanation:     { type: Type.STRING },
            riskFactors:     { type: Type.ARRAY, items: { type: Type.STRING } },
            recommendedAction: { type: Type.STRING },
          },
          required: ["spamScore", "phishingScore", "threatScore", "confidenceScore", "riskLevel", "classification", "explanation", "riskFactors", "recommendedAction"],
        },
      },
    });

    const parsedResponse = JSON.parse(result.text.trim());
    parsedResponse.riskLevel = normalizeRisk(parsedResponse.riskLevel, Math.max(parsedResponse.threatScore ?? 0, parsedResponse.phishingScore ?? 0));
    parsedResponse.classification = normalizeClass(parsedResponse.classification, parsedResponse.riskLevel);
    res.json({ success: true, results: parsedResponse });
  } catch (error: any) {
    console.error("SMS scan error:", error);
    res.status(500).json({ error: geminiError(error, "SMS analysis failed. Please try again.") });
  }
});

/**
 * 5. MANUAL COLD TEXT SCANNER
 */
app.post("/api/scan/manual", requireUser, async (req, res) => {
  const { sender, subject, content } = req.body;

  if (!sender || !content) {
    return res.status(400).json({ error: "Sender and Content fields are required for manual assessment." });
  }

  try {
    const analysisPrompt = `Analyze this email for security issues. Identify spam indicators, fraudulent URLs, phishing contexts, malicious intents, or scams.
Sender: ${sender}
Subject: ${subject || "No Subject"}
Email Body Content:
${content}

You must return a rigorous security risk assessment strictly matching the JSON schema.`;

    const result = await generate({
      model: GEMINI_MODEL,
      contents: analysisPrompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            spamScore: { type: Type.INTEGER, description: "Score from 0 to 100" },
            phishingScore: { type: Type.INTEGER, description: "Score from 0 to 100" },
            threatScore: { type: Type.INTEGER, description: "Score from 0 to 100" },
            confidenceScore: { type: Type.INTEGER, description: "Confidence score from 0 to 100" },
            riskLevel: { type: Type.STRING, enum: RISK_LEVELS },
            classification: { type: Type.STRING, enum: CLASSIFICATIONS },
            explanation: { type: Type.STRING, description: "Explanation of findings" },
            riskFactors: { type: Type.ARRAY, items: { type: Type.STRING }, description: "Specific indicators flagged" },
            recommendedAction: { type: Type.STRING, description: "Recommended response action" },
          },
          required: [
            "spamScore",
            "phishingScore",
            "threatScore",
            "confidenceScore",
            "riskLevel",
            "classification",
            "explanation",
            "riskFactors",
            "recommendedAction",
          ],
        },
      },
    });

    const parsedResponse = JSON.parse(result.text.trim());
    parsedResponse.riskLevel = normalizeRisk(parsedResponse.riskLevel, Math.max(parsedResponse.threatScore ?? 0, parsedResponse.phishingScore ?? 0));
    parsedResponse.classification = normalizeClass(parsedResponse.classification, parsedResponse.riskLevel);
    res.json({ success: true, results: parsedResponse });
  } catch (error: any) {
    console.error("Error manually scanning content:", error);
    res.status(500).json({ error: geminiError(error, "AI Scanner Engine failed to analyze content. Please try again.") });
  }
});

/**
 * 4. REAL GMAIL SYNC & SCAN LOGIC WITH OAUTH TOKEN (OR SANDBOX SIMULATION FALLBACK)
 */
app.post("/api/gmail/sync", requireUser, async (req, res) => {
  const userId = req.user!.id;
  const googleAccessToken = await getGoogleToken(req);

  // Pre-configured high-fidelity simulated feeds for iframe dev testing environments
  const simulatedMails = [
    {
      id: "sim_msg_phish_001",
      from: "Netflix Support <no-reply-billing@netflix-secure-update.com>",
      to: "user@example.com",
      subject: "Urgent: Redetecting your billing method. Suspended account alert!",
      date: new Date(Date.now() - 10 * 60 * 1000).toUTCString(),
      snippet: "We were unable to process your monthly subscription payment. Complete identification check to unlock your digital assets immediately.",
      body: "Dear Customer, We recently had a payment processing issue with your profile. To maintain uninterrupted access to our streaming server, update your verification records. Click here to open Netflix Invoice Center: http://netflix-billing-update-99a3.net/invoice/pay."
    },
    {
      id: "sim_msg_malware_002",
      from: "HR Operations <hr-internal@company-records.net>",
      to: "user@example.com",
      subject: "Urgent Action: Download and review latest corporate bonus list Q2",
      date: new Date(Date.now() - 40 * 60 * 1000).toUTCString(),
      snippet: "All active team members are authorized to download the performance-indexed company bonuses checklist. Secure file inside.",
      body: "Hi team, find the Q2 Corporate Bonuses list in the file folder document attached as 'Bonus_Structure_Q2_Final_Secure.exe'. Run this security executable locally to generate your private verification credentials. Do not share outside the firewall."
    },
    {
      id: "sim_msg_spam_003",
      from: "Solana Alpha Launches <newsletters@solana-airdrop-news.org>",
      to: "user@example.com",
      subject: "Double your SOL wallet with early access smart contract (Limit 50 slots)",
      date: new Date(Date.now() - 120 * 60 * 1000).toUTCString(),
      snippet: "Claim your special 5x multiplier Web3 token. Connect your phantom wallet to gain allocation in decentralized cloud.",
      body: "Web3 Solana Token Airdrop is live. Gain massive investment options with decentralized cloud security layers. Open our decentralized launchpad at http://solana-multiplier-airdrop-protocol.xyz to participate. Terms apply."
    },
    {
      id: "sim_msg_transactional_004",
      from: "GitHub Notifications <notifications@github.com>",
      to: "user@example.com",
      subject: "[GitHub] Security Alert: New SSH key added to your profile",
      date: new Date(Date.now() - 220 * 60 * 1000).toUTCString(),
      snippet: "An active SSH security certificate was successfully authorized on your main account. Review details to confirm identity.",
      body: "We are notifying you that an active SSH credential keyset was uploaded to user account profile on June 04. Location: Dublin, IE. Device: Linux machine. If this was not you, please audit your repository permissions or remove the key immediately."
    },
    {
      id: "sim_msg_safe_005",
      from: "Team Lead <sarah.jenkins@company-internal.com>",
      to: "user@example.com",
      subject: "Weekly sync meeting agenda & Q2 team deliverables",
      date: new Date(Date.now() - 420 * 60 * 1000).toUTCString(),
      snippet: "Hey team, let's assemble on Monday for our engineering weekly sync. Read inside for milestones and status reports.",
      body: "Hi all, hoping everyone had an excellent week. For Monday's weekly sync, let's discuss our progress on the Gemini Threat Scanner applet integration. Sarah will summarize our user feedback. See you then!"
    }
  ];

  let messages: any[] = [];
  let hasMore = false;
  let isSimulated = !googleAccessToken;
  const isScanned = db.prepare("SELECT 1 FROM emails WHERE userId = ? AND id = ?");
  const alreadyScanned = (id: string) => Boolean(isScanned.get(userId, id));

  if (!isSimulated) {
    try {
      // Page through the inbox (newest first), collecting messages not scanned yet
      let pageToken: string | undefined;
      do {
        const listUrl = new URL("https://gmail.googleapis.com/gmail/v1/users/me/messages");
        listUrl.searchParams.set("maxResults", "100");
        listUrl.searchParams.set("labelIds", "INBOX");
        if (pageToken) listUrl.searchParams.set("pageToken", pageToken);
        const gmailListRes = await fetch(listUrl, { headers: { Authorization: `Bearer ${googleAccessToken}` } });
        if (!gmailListRes.ok) throw new Error(`Gmail list failed (${gmailListRes.status})`);
        const listData = await gmailListRes.json();
        for (const m of listData.messages || []) {
          if (alreadyScanned(m.id)) continue;
          if (messages.length >= SYNC_BATCH) hasMore = true;
          else messages.push(m);
        }
        pageToken = hasMore ? undefined : listData.nextPageToken;
      } while (pageToken);
    } catch (err) {
      console.warn("Gmail API error, falling back to simulated sandbox feed:", err);
      isSimulated = true;
      messages = [];
    }
  }

  if (isSimulated) {
    messages = simulatedMails.filter(m => !alreadyScanned(m.id)).map(m => ({ id: m.id }));
  }

  try {
    const scannedReports = [];

    // 2. Load stored customized rules for this user
    const activeRules: any[] = db.prepare("SELECT * FROM rules WHERE userId = ?").all(userId).map((r: any) => ({ ...r, active: Boolean(r.active) }));

    // Helper to extract message payload headers
    const getHeader = (headers: any[], name: string) => {
      const found = headers?.find(h => h.name?.toLowerCase() === name.toLowerCase());
      return found ? found.value : "";
    };

    // Helper to decode base64 bodies recursively
    const getBodyContent = (payload: any): string => {
      if (!payload) return "";
      if (payload.body && payload.body.data) {
        const cleanBase64 = payload.body.data.replace(/-/g, "+").replace(/_/g, "/");
        return Buffer.from(cleanBase64, "base64").toString("utf-8");
      }
      if (payload.parts) {
        for (const part of payload.parts) {
          if (part.mimeType === "text/plain" && part.body && part.body.data) {
            const cleanBase64 = part.body.data.replace(/-/g, "+").replace(/_/g, "/");
            return Buffer.from(cleanBase64, "base64").toString("utf-8");
          }
          if (part.parts) {
            const nestedBody = getBodyContent(part);
            if (nestedBody) return nestedBody;
          }
        }
      }
      return "";
    };

    // Keep list of existing Gmail Labels to prevent redundant creations
    let existingLabels: any[] = [];
    if (!isSimulated) {
      try {
        const labelsRes = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/labels", {
          headers: { Authorization: `Bearer ${googleAccessToken}` },
        });
        if (labelsRes.ok) {
          const labelsData = await labelsRes.json();
          existingLabels = labelsData.labels || [];
        }
      } catch (labelsErr) {
        console.warn("Could not query labels", labelsErr);
      }
    }

    // Load every new message's content (10 at a time), then scan them in batches
    const loaded = await mapPool(messages, 10, async (msg): Promise<MailItem | null> => {
      if (isSimulated) {
        const m = simulatedMails.find(x => x.id === msg.id);
        return m ? { id: m.id, from: m.from, to: m.to, subject: m.subject, date: m.date, snippet: m.snippet, bodyText: m.body } : null;
      }
      try {
        const msgRes = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`, {
          headers: { Authorization: `Bearer ${googleAccessToken}` },
        });
        if (!msgRes.ok) return null;
        const msgData = await msgRes.json();
        const headers = msgData.payload?.headers || [];
        const snippet = msgData.snippet || "";
        return {
          id: msg.id,
          from: getHeader(headers, "From"),
          to: getHeader(headers, "To"),
          subject: getHeader(headers, "Subject") || "(No Subject)",
          date: getHeader(headers, "Date"),
          snippet,
          bodyText: getBodyContent(msgData.payload) || snippet,
        };
      } catch {
        return null;
      }
    });
    const items = loaded.filter((m): m is MailItem => m !== null);
    const scanResults = await scanEmails(items);

    for (const item of items) {
      const msg = { id: item.id };
      const { from: fromHeader, to: toHeader, subject: subjectHeader, date: dateHeader, snippet } = item;
      const securityResult = scanResults.get(item.id);
      if (!securityResult) continue; // scan failed; picked up again on the next sync
      securityResult.riskLevel = normalizeRisk(securityResult.riskLevel, Math.max(securityResult.threatScore ?? 0, securityResult.phishingScore ?? 0));
      securityResult.classification = normalizeClass(securityResult.classification, securityResult.riskLevel);
      const classKey = securityResult.classification?.toLowerCase() || "";
      const appliedLabels: string[] = [];

      // 3. APPLY RULES IN REAL TIME (Gmail label modifications)
      const matchedRule = activeRules.find(r => r.active && r.emailType?.toLowerCase() === classKey);

      if (matchedRule) {
        try {
          const ruleAction = matchedRule.action;
          const labelName = matchedRule.labelName || `SecureBox/${securityResult.classification}`;

          if (ruleAction === "label") {
            let labelId = "simulated_label_id";
            if (!isSimulated) {
              // Find or create label ID in Gmail
              const foundLabel = existingLabels.find(l => l.name?.toLowerCase() === labelName.toLowerCase());
              labelId = foundLabel?.id || "";
              
              if (!labelId) {
                const createLabelRes = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/labels", {
                  method: "POST",
                  headers: {
                    Authorization: `Bearer ${googleAccessToken}`,
                    "Content-Type": "application/json",
                  },
                  body: JSON.stringify({
                    name: labelName,
                    labelListVisibility: "labelShow",
                    messageListVisibility: "show",
                  }),
                });

                if (createLabelRes.ok) {
                  const newLabel = await createLabelRes.json();
                  labelId = newLabel.id;
                  existingLabels.push(newLabel);
                }
              }

              if (labelId) {
                // Apply this created Google label onto real active mail
                await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}/modify`, {
                  method: "POST",
                  headers: {
                    Authorization: `Bearer ${googleAccessToken}`,
                    "Content-Type": "application/json",
                  },
                  body: JSON.stringify({
                    addLabelIds: [labelId],
                    removeLabelIds: [],
                  }),
                });
              }
            }

            if (labelId || isSimulated) {
              appliedLabels.push(labelName);

              // Log trigger audit
              logActivity(userId, `Rule Triggered: Label "${labelName}" applied onto ${isSimulated ? "sandbox-simulated" : "threat"} email "${subjectHeader}" from ${fromHeader}`, "rules");
            }
          } else if (ruleAction === "archive") {
            if (!isSimulated) {
              await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}/modify`, {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${googleAccessToken}`,
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  addLabelIds: [],
                  removeLabelIds: ["INBOX"],
                }),
              });
            }
            appliedLabels.push("Archived");
            logActivity(userId, `Rule Triggered: Auto-Archived ${isSimulated ? "sandbox-simulated" : "threat"} email "${subjectHeader}"`, "rules");
          } else if (ruleAction === "mark_read") {
            if (!isSimulated) {
              await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}/modify`, {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${googleAccessToken}`,
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  addLabelIds: [],
                  removeLabelIds: ["UNREAD"],
                }),
              });
            }
            appliedLabels.push("Marked Read");
            logActivity(userId, `Rule Triggered: Marked ${isSimulated ? "sandbox-simulated" : "threat"} email "${subjectHeader}" as Read`, "rules");
          } else if (ruleAction === "move_trash") {
            if (!isSimulated) {
              await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}/trash`, {
                method: "POST",
                headers: { Authorization: `Bearer ${googleAccessToken}` },
              });
            }
            appliedLabels.push("Trashed");
            logActivity(userId, `Rule Triggered: Moved ${isSimulated ? "sandbox-simulated" : "threat"} email "${subjectHeader}" to Trash`, "rules");
          }
        } catch (ruleError) {
          console.error("Failed to execute inbox organization actions:", ruleError);
        }
      }

      // Compile output document
      const docPayload = {
        id: msg.id,
        userId,
        from: fromHeader,
        to: toHeader,
        subject: subjectHeader,
        date: dateHeader || new Date().toISOString(),
        snippet: snippet,
        spamScore: Number(securityResult.spamScore ?? 0),
        phishingScore: Number(securityResult.phishingScore ?? 0),
        threatScore: Number(securityResult.threatScore ?? 0),
        confidenceScore: Number(securityResult.confidenceScore ?? 85),
        riskLevel: securityResult.riskLevel || "Safe",
        explanation: securityResult.explanation || "No details provided.",
        riskFactors: securityResult.riskFactors || [],
        recommendedAction: securityResult.recommendedAction || "None",
        classification: securityResult.classification || "Personal",
        appliedGmailLabels: appliedLabels,
        scannedAt: new Date().toISOString(),
      };

      db.prepare("INSERT OR REPLACE INTO emails (id, userId, data, scannedAt) VALUES (?, ?, ?, ?)")
        .run(msg.id, userId, JSON.stringify(docPayload), docPayload.scannedAt);

      // Create log trigger log entry
      logActivity(userId, `Automatic email scan performed: Flagged "${subjectHeader}" from ${fromHeader} as ${securityResult.riskLevel} (${securityResult.classification})`, "security");

      scannedReports.push(docPayload);
    }

    res.json({ success: true, scanned: scannedReports.length, remaining: hasMore || (scannedReports.length < messages.length && messages.length > 0), reports: scannedReports });
  } catch (error: any) {
    console.error("Gmail sync error:", error);
    res.status(500).json({ error: geminiError(error, "Failed to securely parse and sync Gmail messages with Gemini AI.") });
  }
});

// Vite middleware development / production handler
async function startViteMiddleware() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[SecureBox Server] Server running securely inside sandbox on http://localhost:${PORT}`);
  });
}

initDatabase().then(startViteMiddleware);
