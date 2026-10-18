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

// Retry transient Gemini failures (overloaded / rate limited) with exponential backoff
async function generate(params: Parameters<typeof ai.models.generateContent>[0], attempts = 4) {
  for (let i = 0; ; i++) {
    try {
      return await ai.models.generateContent(params);
    } catch (err: any) {
      const transient = [429, 500, 503, 504].includes(err?.status);
      if (!transient || i >= attempts - 1) throw err;
      await new Promise((r) => setTimeout(r, 1000 * 2 ** i));
    }
  }
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
 * 3. MANUAL COLD TEXT SCANNER
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
      model: "gemini-3.5-flash",
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
  let isSimulated = !googleAccessToken;

  if (!isSimulated) {
    try {
      // 1. Fetch latest emails from Google Gmail API
      const listUrl = "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=8";
      const gmailListRes = await fetch(listUrl, {
        headers: { Authorization: `Bearer ${googleAccessToken}` },
      });

      if (gmailListRes.ok) {
        const listData = await gmailListRes.json();
        messages = listData.messages || [];
      } else {
        console.warn("Gmail API listing failure, falling back to simulated sandbox feed.");
        isSimulated = true;
      }
    } catch (err) {
      console.warn("Gmail API connection error, falling back to simulated sandbox feed:", err);
      isSimulated = true;
    }
  }

  if (isSimulated) {
    messages = simulatedMails.map(m => ({ id: m.id }));
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

    for (const msg of messages) {
      const cached = db.prepare("SELECT data FROM emails WHERE userId = ? AND id = ?").get(userId, msg.id) as { data: string } | undefined;
      if (cached) {
        // Already scanned and stored
        scannedReports.push(JSON.parse(cached.data));
        continue;
      }

      let fromHeader = "";
      let toHeader = "";
      let subjectHeader = "";
      let dateHeader = "";
      let snippet = "";
      let bodyText = "";

      if (isSimulated) {
        const matchingMail = simulatedMails.find(m => m.id === msg.id);
        if (!matchingMail) continue;
        fromHeader = matchingMail.from;
        toHeader = matchingMail.to;
        subjectHeader = matchingMail.subject;
        dateHeader = matchingMail.date;
        snippet = matchingMail.snippet;
        bodyText = matchingMail.body;
      } else {
        // Fetch detail message
        const detailUrl = `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`;
        const msgRes = await fetch(detailUrl, {
          headers: { Authorization: `Bearer ${googleAccessToken}` },
        });

        if (!msgRes.ok) continue;
        const msgData = await msgRes.json();

        const headers = msgData.payload?.headers || [];
        fromHeader = getHeader(headers, "From");
        toHeader = getHeader(headers, "To");
        subjectHeader = getHeader(headers, "Subject") || "(No Subject)";
        dateHeader = getHeader(headers, "Date");
        snippet = msgData.snippet || "";
        bodyText = getBodyContent(msgData.payload) || snippet;
      }

      // Ask Gemini to scan this particular email body
      const riskPrompt = `Please analyze the security and safety posture of this email inbox item:
From: ${fromHeader}
To: ${toHeader}
Subject: ${subjectHeader}
Date: ${dateHeader}
Snippet: ${snippet}
Message content:
${bodyText}

Produce a complete audit report strictly matching the JSON schema requested.`;

      let aiResponse;
      try {
        aiResponse = await generate({
        model: "gemini-3.5-flash",
        contents: riskPrompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              spamScore: { type: Type.INTEGER },
              phishingScore: { type: Type.INTEGER },
              threatScore: { type: Type.INTEGER },
              confidenceScore: { type: Type.INTEGER },
              riskLevel: { type: Type.STRING, enum: RISK_LEVELS },
              classification: { type: Type.STRING, enum: CLASSIFICATIONS },
              explanation: { type: Type.STRING },
              riskFactors: { type: Type.ARRAY, items: { type: Type.STRING } },
              recommendedAction: { type: Type.STRING },
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
      } catch (err: any) {
        if (err?.status === 401 || err?.status === 403) throw err;
        console.warn(`Skipping message ${msg.id}: Gemini scan failed (${err?.status || err?.message})`);
        continue;
      }

      const securityResult = JSON.parse(aiResponse.text.trim());
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

    res.json({ success: true, reports: scannedReports });
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
