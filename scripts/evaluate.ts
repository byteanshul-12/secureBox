/**
 * scripts/evaluate.ts
 *
 * Evaluates the SecureBox AI scanner against a labelled dataset.
 * Prints precision, recall, F1-score and accuracy for threat detection.
 *
 * Usage:
 *   npx tsx scripts/evaluate.ts
 *
 * Requires:  GEMINI_API_KEY set in .env or environment.
 */

import "dotenv/config";
import { GoogleGenAI, Type } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

// ── Labelled Dataset ─────────────────────────────────────────────────────────
// label: true = malicious/suspicious, false = legitimate
const DATASET: Array<{
  id: string;
  sender: string;
  subject: string;
  body: string;
  label: boolean; // ground truth: true = threat
  channel: "email" | "sms";
}> = [
  // PHISHING / MALICIOUS
  {
    id: "ev_01",
    channel: "email",
    label: true,
    sender: "security@paypal-account-update.net",
    subject: "Action Required: Verify your account or it will be suspended",
    body: "Dear Customer, we detected suspicious activity. Click here immediately: http://paypal-secure-login.xyz/verify to avoid permanent account suspension.",
  },
  {
    id: "ev_02",
    channel: "email",
    label: true,
    sender: "hr@company-bonuses-2024.info",
    subject: "Q3 Bonus Release - Download Your Certificate Now",
    body: "Hi team, your Q3 performance bonus certificate is ready. Download the attached executable: BonusCert_Q3.exe and run it to unlock your certificate.",
  },
  {
    id: "ev_03",
    channel: "sms",
    label: true,
    sender: "HDFC-BANK",
    subject: "",
    body: "URGENT: Your HDFC account will be blocked. Update KYC immediately at http://hdfc-kyc-update.xyz/verify?token=8821 or call 1800-000-123.",
  },
  {
    id: "ev_04",
    channel: "email",
    label: true,
    sender: "noreply@netflix-billing-alert.com",
    subject: "Payment Failed - Update your billing info within 24 hours",
    body: "Your Netflix subscription payment failed. To keep your access update billing at http://netflix-payment-center-secure.net. Failure results in termination.",
  },
  {
    id: "ev_05",
    channel: "sms",
    label: true,
    sender: "+1-888-555-9120",
    subject: "",
    body: "Congratulations! You won $5000 in our lottery. Claim prize at http://prize-claim-now.xyz/win?ref=A8821 within 2 hours or forfeit.",
  },
  {
    id: "ev_06",
    channel: "email",
    label: true,
    sender: "it-support@companysecurelogin.net",
    subject: "IT ALERT: Reset your VPN credentials immediately",
    body: "All employees must reset VPN credentials due to a breach. Use this link: http://vpn-corp-reset.xyz/auth?emp=true — IT Security Team.",
  },
  {
    id: "ev_07",
    channel: "email",
    label: true,
    sender: "invest@crypto-guaranteed-returns.io",
    subject: "5x your crypto in 30 days - Limited time offer",
    body: "Join our exclusive DeFi yield farming protocol. Connect your wallet at http://defi-yield-xyz.io/stake and earn guaranteed 500% APY.",
  },
  {
    id: "ev_08",
    channel: "sms",
    label: true,
    sender: "GOV-TAX",
    subject: "",
    body: "Income Tax Dept: You have a pending refund of Rs 18,450. Click http://incometax-refund-india.xyz/apply?pan=XXXXX to claim within 48 hrs.",
  },

  // LEGITIMATE
  {
    id: "ev_09",
    channel: "email",
    label: false,
    sender: "sarah.jenkins@company-internal.com",
    subject: "Weekly sync meeting agenda",
    body: "Hi all, let's meet Monday for our weekly sync. Agenda: Q3 deliverables review, team retrospective. Calendar invite sent separately.",
  },
  {
    id: "ev_10",
    channel: "email",
    label: false,
    sender: "notifications@github.com",
    subject: "[GitHub] New SSH key added to your account",
    body: "A new SSH key was added to your GitHub account. If this was you, no action needed. If not, visit https://github.com/settings/security to review.",
  },
  {
    id: "ev_11",
    channel: "sms",
    label: false,
    sender: "+91-98765-43210",
    subject: "",
    body: "Hi! Just confirming our meeting at 10 AM tomorrow. Please bring the project report. Let me know if you need to reschedule. - Priya",
  },
  {
    id: "ev_12",
    channel: "email",
    label: false,
    sender: "no-reply@amazon.com",
    subject: "Your Amazon order has shipped",
    body: "Hello, your order #114-2938471-1928374 has shipped and will arrive by Thursday. Track at https://www.amazon.com/orders. Amazon Customer Service.",
  },
  {
    id: "ev_13",
    channel: "email",
    label: false,
    sender: "team@notion.so",
    subject: "Your Notion workspace weekly digest",
    body: "Here's what happened in your workspace this week: 3 new pages, 5 comments. Check your workspace at https://notion.so/dashboard.",
  },
  {
    id: "ev_14",
    channel: "sms",
    label: false,
    sender: "AMAZON",
    subject: "",
    body: "Your Amazon OTP is 847291. Valid for 10 minutes. Do not share this code with anyone. Amazon will never ask for this code.",
  },
  {
    id: "ev_15",
    channel: "email",
    label: false,
    sender: "jessica.kline@firmwork-solutions.com",
    subject: "Q3 Project Milestone deliverables review call",
    body: "Hi team, hoping everyone had an excellent week. For Thursday's call let's discuss Q3 milestone progress. Sarah will summarize user feedback. Invite sent.",
  },
  {
    id: "ev_16",
    channel: "sms",
    label: false,
    sender: "HDFC-BANK",
    subject: "",
    body: "Your HDFC account XXXX1234 credited Rs 25,000 on 18-Oct. Avail bal Rs 52,430. If not done by you call 1800-258-3838. -HDFC Bank",
  },
];

// ── Scanner ──────────────────────────────────────────────────────────────────
const RISK_LEVELS = ["Safe", "Low Risk", "Medium Risk", "High Risk", "Critical"];
const THREAT_CLASSES = ["Phishing", "Scam", "Spam", "Suspicious"];

async function classifySample(sample: (typeof DATASET)[0]): Promise<{
  predicted: boolean;
  riskLevel: string;
  classification: string;
  confidence: number;
  explanation: string;
}> {
  const prompt =
    sample.channel === "email"
      ? `Analyze this email for phishing, scam, spam, or social-engineering threats.\nFrom: ${sample.sender}\nSubject: ${sample.subject}\nBody:\n${sample.body}`
      : `Analyze this SMS message for phishing (smishing), scam, or social-engineering threats.\nSender: ${sample.sender}\nMessage:\n${sample.body}`;

  const response = await ai.models.generateContent({
    model: MODEL,
    contents: prompt,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          riskLevel: { type: Type.STRING, enum: RISK_LEVELS },
          classification: {
            type: Type.STRING,
            enum: ["Important", "Personal", "Work", "Newsletter", "Promotion", "Marketing", "Cold Outreach", "Spam", "Phishing", "Scam", "Suspicious"],
          },
          confidenceScore: { type: Type.INTEGER, description: "0-100" },
          explanation: { type: Type.STRING },
        },
        required: ["riskLevel", "classification", "confidenceScore", "explanation"],
      },
    },
  });

  const parsed = JSON.parse(response.text.trim());
  const predicted = THREAT_CLASSES.includes(parsed.classification) ||
    parsed.riskLevel === "High Risk" ||
    parsed.riskLevel === "Critical";

  return {
    predicted,
    riskLevel: parsed.riskLevel,
    classification: parsed.classification,
    confidence: parsed.confidenceScore,
    explanation: parsed.explanation,
  };
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log("\n╔══════════════════════════════════════════════════════════╗");
  console.log("║   SecureBox AI – Evaluation Against Labelled Dataset    ║");
  console.log("╚══════════════════════════════════════════════════════════╝\n");
  console.log(`Model: ${MODEL}`);
  console.log(`Dataset size: ${DATASET.length} samples (${DATASET.filter(d => d.label).length} threats, ${DATASET.filter(d => !d.label).length} legitimate)\n`);
  console.log("Running evaluation...\n");

  const results: Array<{
    id: string;
    channel: string;
    groundTruth: boolean;
    predicted: boolean;
    riskLevel: string;
    classification: string;
    confidence: number;
    correct: boolean;
  }> = [];

  for (const sample of DATASET) {
    process.stdout.write(`  [${sample.id}] ${sample.channel.toUpperCase()} – "${sample.subject || sample.body.slice(0, 40)}..." → `);
    try {
      const result = await classifySample(sample);
      const correct = result.predicted === sample.label;
      results.push({
        id: sample.id,
        channel: sample.channel,
        groundTruth: sample.label,
        predicted: result.predicted,
        riskLevel: result.riskLevel,
        classification: result.classification,
        confidence: result.confidence,
        correct,
      });
      const icon = correct ? "✓" : "✗";
      const label = result.predicted ? `THREAT (${result.riskLevel})` : "SAFE";
      console.log(`${icon}  Predicted: ${label} | GT: ${sample.label ? "THREAT" : "SAFE"} | ${result.classification} (${result.confidence}%)`);
    } catch (err: any) {
      console.log(`ERROR: ${err.message}`);
      results.push({
        id: sample.id, channel: sample.channel,
        groundTruth: sample.label, predicted: false,
        riskLevel: "Unknown", classification: "Unknown", confidence: 0, correct: false,
      });
    }
    // Small delay to avoid rate limits
    await new Promise(r => setTimeout(r, 500));
  }

  // ── Compute Metrics ──────────────────────────────────────────────────────
  const TP = results.filter(r => r.groundTruth && r.predicted).length;
  const TN = results.filter(r => !r.groundTruth && !r.predicted).length;
  const FP = results.filter(r => !r.groundTruth && r.predicted).length;
  const FN = results.filter(r => r.groundTruth && !r.predicted).length;

  const accuracy   = ((TP + TN) / results.length) * 100;
  const precision  = TP + FP > 0 ? (TP / (TP + FP)) * 100 : 0;
  const recall     = TP + FN > 0 ? (TP / (TP + FN)) * 100 : 0;
  const f1         = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const fpr        = FP + TN > 0 ? (FP / (FP + TN)) * 100 : 0;

  console.log("\n╔══════════════════════════════════════════════════════════╗");
  console.log("║                  EVALUATION RESULTS                     ║");
  console.log("╠══════════════════════════════════════════════════════════╣");
  console.log(`║  Total Samples : ${String(results.length).padEnd(38)}║`);
  console.log(`║  Correct       : ${String(results.filter(r => r.correct).length).padEnd(38)}║`);
  console.log("╠══════════════════════════════════════════════════════════╣");
  console.log(`║  Accuracy      : ${accuracy.toFixed(1).padEnd(37)}%║`);
  console.log(`║  Precision     : ${precision.toFixed(1).padEnd(37)}%║`);
  console.log(`║  Recall        : ${recall.toFixed(1).padEnd(37)}%║`);
  console.log(`║  F1-Score      : ${f1.toFixed(1).padEnd(37)}%║`);
  console.log(`║  False Pos Rate: ${fpr.toFixed(1).padEnd(37)}%║`);
  console.log("╠══════════════════════════════════════════════════════════╣");
  console.log(`║  TP=${TP}  TN=${TN}  FP=${FP}  FN=${FN}${" ".repeat(38 - `TP=${TP}  TN=${TN}  FP=${FP}  FN=${FN}`.length)}║`);
  console.log("╚══════════════════════════════════════════════════════════╝\n");

  // Misclassifications
  const misses = results.filter(r => !r.correct);
  if (misses.length > 0) {
    console.log("Misclassified samples:");
    for (const m of misses) {
      console.log(`  [${m.id}] GT=${m.groundTruth ? "THREAT" : "SAFE"} → Predicted=${m.predicted ? "THREAT" : "SAFE"} (${m.riskLevel} / ${m.classification})`);
    }
  }
}

main().catch(err => {
  console.error("Evaluation failed:", err.message);
  process.exit(1);
});
