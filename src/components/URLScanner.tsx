import React, { useState } from "react";
import { Link2, ChevronLeft, AlertTriangle, FileText, CheckCircle2, MessageSquare, Globe } from "lucide-react";

interface ScannerProps {
  onBackToDashboard: () => void;
}

interface URLScanResult {
  url: string;
  isMalicious: boolean;
  riskLevel: "Safe" | "Low Risk" | "Medium Risk" | "High Risk" | "Critical";
  riskScore: number;
  confidenceScore: number;
  explanation: string;
  riskFactors: string[];
  urlFeatures: {
    domain: string;
    tld: string;
    hasHttps: boolean;
    subdomainCount: number;
    pathDepth: number;
    hasIPAddress: boolean;
    suspiciousKeywords: string[];
    urlLength: number;
    hasPort: boolean;
    hasEncodedChars: boolean;
  };
  recommendedAction: string;
}

interface SMSScanResult {
  spamScore: number;
  phishingScore: number;
  threatScore: number;
  confidenceScore: number;
  riskLevel: "Safe" | "Low Risk" | "Medium Risk" | "High Risk" | "Critical";
  classification: string;
  explanation: string;
  riskFactors: string[];
  recommendedAction: string;
}

export default function URLScanner({ onBackToDashboard }: ScannerProps) {
  const [urlInput, setUrlInput] = useState("");
  const [urlLoading, setUrlLoading] = useState(false);
  const [urlResult, setUrlResult] = useState<URLScanResult | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);

  const [smsSender, setSmsSender] = useState("");
  const [smsContent, setSmsContent] = useState("");
  const [smsLoading, setSmsLoading] = useState(false);
  const [smsResult, setSmsResult] = useState<SMSScanResult | null>(null);
  const [smsError, setSmsError] = useState<string | null>(null);

  const [activeMode, setActiveMode] = useState<"url" | "sms">("url");

  const handleURLScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    setUrlLoading(true);
    setUrlResult(null);
    setUrlError(null);
    try {
      const res = await fetch("/api/scan/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlInput.trim() }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || "URL scan failed");
      }
      const data = await res.json();
      if (data.success) setUrlResult(data.result);
      else throw new Error(data.error || "URL scan failed");
    } catch (err: any) {
      setUrlError(err.message || "URL scan failed");
    } finally {
      setUrlLoading(false);
    }
  };

  const handleSMSScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!smsSender.trim() || !smsContent.trim()) return;
    setSmsLoading(true);
    setSmsResult(null);
    setSmsError(null);
    try {
      const res = await fetch("/api/scan/sms", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sender: smsSender.trim(), content: smsContent.trim() }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || "SMS scan failed");
      }
      const data = await res.json();
      if (data.success) setSmsResult(data.results);
      else throw new Error(data.error || "SMS scan failed");
    } catch (err: any) {
      setSmsError(err.message || "SMS scan failed");
    } finally {
      setSmsLoading(false);
    }
  };

  const tabBtn = (mode: "url" | "sms") =>
    `flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-display font-black border-2 border-black transition-all cursor-pointer ${
      activeMode === mode
        ? "bg-[#4F8CFF] text-white shadow-[2px_2px_0px_0px_rgba(0,0,0,1)]"
        : "bg-white text-slate-800 hover:bg-slate-50 shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[3px_3px_0px_0px_rgba(0,0,0,1)]"
    }`;

  return (
    <div className="min-h-screen bg-[#F8F7F4] text-slate-900 p-6 md:p-8 font-sans relative overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#00000008_1px,transparent_1px),linear-gradient(to_bottom,#00000008_1px,transparent_1px)] bg-[size:40px_40px] pointer-events-none" />

      <div className="max-w-4xl mx-auto space-y-8 text-left relative z-10">
        <button
          onClick={onBackToDashboard}
          className="inline-flex items-center gap-2 px-3 py-1.5 bg-white hover:bg-black/5 text-xs font-display font-black text-slate-900 uppercase border-2 border-black rounded-lg shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[3.5px_3.5px_0px_0px_rgba(0,0,0,1)] active:translate-x-0 active:translate-y-0 transition-all cursor-pointer"
        >
          <ChevronLeft className="w-4 h-4 stroke-[2.5]" />
          Back to Dashboard
        </button>

        <header className="pb-6 border-b-4 border-black flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <div>
            <h2 className="font-display font-black text-2xl md:text-3xl tracking-tight text-slate-950">
              URL &amp; SMS Threat Scanner
            </h2>
            <p className="text-xs text-slate-800 font-bold mt-1 max-w-xl leading-relaxed">
              Analyse suspicious links for phishing indicators or scan SMS messages for social-engineering patterns using Gemini AI.
            </p>
          </div>
          <div className="flex gap-2 shrink-0">
            <button className={tabBtn("url")} onClick={() => setActiveMode("url")}>
              <Globe className="w-3.5 h-3.5 stroke-[2.5]" />
              URL Checker
            </button>
            <button className={tabBtn("sms")} onClick={() => setActiveMode("sms")}>
              <MessageSquare className="w-3.5 h-3.5 stroke-[2.5]" />
              SMS Scanner
            </button>
          </div>
        </header>

        {/* URL MODE */}
        {activeMode === "url" && (
          <div className="grid md:grid-cols-2 gap-8 items-start">
            <form onSubmit={handleURLScan} className="bg-white rounded-xl border-4 border-black p-6 space-y-4 shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
              <h3 className="font-display text-base font-black text-slate-950 border-b-2 border-black pb-2">Submit URL for Analysis</h3>
              {urlError && (
                <div className="p-3 bg-red-100 border-2 border-black text-red-950 text-xs font-bold rounded-lg flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-red-700" />
                  {urlError}
                </div>
              )}
              <div className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-800 font-mono font-bold uppercase tracking-wider mb-1.5">URL or Link</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. http://paypal-login.xyz/verify"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    className="w-full px-4 py-2.5 bg-white border-2 border-black rounded-lg text-slate-900 font-bold focus:outline-none focus:ring-2 focus:ring-[#4F8CFF] shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] font-mono"
                  />
                </div>
              </div>
              <div className="flex gap-2">
                <button type="button" onClick={() => setUrlInput("http://paypal-login-secure-update.xyz/verify?token=abc123")}
                  className="px-3.5 py-2 bg-[#FFEED4] border-2 border-black text-rose-950 text-xs font-extrabold rounded-lg shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] hover:bg-[#ffdcb0] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] transition-all cursor-pointer">
                  Load Malicious
                </button>
                <button type="button" onClick={() => setUrlInput("https://github.com/openai/openai-python")}
                  className="px-3.5 py-2 bg-emerald-100 border-2 border-black text-emerald-950 text-xs font-extrabold rounded-lg shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] hover:bg-emerald-200 hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] transition-all cursor-pointer">
                  Load Safe
                </button>
              </div>
              <button id="submit-url-scan-btn" type="submit" disabled={urlLoading}
                className={`w-full py-3.5 rounded-lg text-sm font-extrabold transition-all border-2 border-black shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_0px_rgba(0,0,0,1)] active:translate-x-0 active:translate-y-0 cursor-pointer ${
                  urlLoading ? "bg-slate-200 text-slate-500 cursor-not-allowed shadow-none hover:translate-x-0 hover:translate-y-0" : "bg-[#4F8CFF] hover:bg-[#3b7ae6] text-white"
                }`}>
                {urlLoading ? "Scanning URL..." : "Analyse URL"}
              </button>
            </form>

            <div className="space-y-6">
              {!urlResult && !urlLoading && (
                <div className="p-12 text-center rounded-xl border-4 border-dashed border-black bg-white/45 flex flex-col items-center justify-center min-h-[300px]">
                  <Link2 className="w-12 h-12 text-slate-400 mb-4 stroke-[1.5]" />
                  <h4 className="font-display font-black text-base text-slate-950 mb-1">URL Analyser Idle</h4>
                  <p className="text-xs text-slate-700 font-bold max-w-xs leading-relaxed">
                    Paste any suspicious link. The engine extracts domain features, TLD signals and keyword patterns before querying Gemini.
                  </p>
                </div>
              )}
              {urlLoading && (
                <div className="p-12 text-center rounded-xl border-4 border-black bg-white flex flex-col items-center justify-center space-y-4 min-h-[300px] shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
                  <div className="w-10 h-10 rounded-lg border-4 border-black bg-white shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] flex items-center justify-center animate-spin">
                    <div className="w-3.5 h-3.5 bg-[#4F8CFF] rounded-sm" />
                  </div>
                  <h4 className="font-display font-black text-xs text-[#4F8CFF] tracking-widest uppercase">EXTRACTING URL FEATURES...</h4>
                </div>
              )}
              {urlResult && (
                <div id="url-scan-result" className="p-6 bg-white rounded-xl border-4 border-black space-y-5 text-left shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
                  <div>
                    <div className="flex items-center justify-between border-b-2 border-black pb-2">
                      <span className="text-[10px] font-mono font-black uppercase tracking-wider">URL ANALYSIS REPORT</span>
                      <span className="px-2.5 py-1.5 rounded-md text-[10px] font-mono font-black bg-[#FFEED4] border-2 border-black shadow-[1.5px_1.5px_0px_0px_rgba(0,0,0,1)]">
                        {urlResult.riskLevel}
                      </span>
                    </div>
                    <p className="font-mono text-[10px] text-slate-500 mt-2 break-all">{urlResult.url}</p>
                  </div>
                  <div className="grid grid-cols-3 gap-3 font-mono text-[10px]">
                    <div className="p-2.5 bg-[#F8F7F4] rounded-lg border-2 border-black shadow-[1.5px_1.5px_0px_0px_rgba(0,0,0,1)]">
                      <div className="text-slate-600 font-bold">Risk Score</div>
                      <div className="text-sm font-black text-rose-600 mt-1">{urlResult.riskScore}%</div>
                    </div>
                    <div className="p-2.5 bg-[#F8F7F4] rounded-lg border-2 border-black shadow-[1.5px_1.5px_0px_0px_rgba(0,0,0,1)]">
                      <div className="text-slate-600 font-bold">Confidence</div>
                      <div className="text-sm font-black text-[#4F8CFF] mt-1">{urlResult.confidenceScore}%</div>
                    </div>
                    <div className="p-2.5 bg-[#F8F7F4] rounded-lg border-2 border-black shadow-[1.5px_1.5px_0px_0px_rgba(0,0,0,1)]">
                      <div className="text-slate-600 font-bold">HTTPS</div>
                      <div className={`text-xs font-black mt-1 ${urlResult.urlFeatures.hasHttps ? "text-emerald-600" : "text-rose-600"}`}>
                        {urlResult.urlFeatures.hasHttps ? "Yes ✓" : "No ✗"}
                      </div>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <h4 className="text-xs font-extrabold text-slate-800 flex items-center gap-1.5">
                      <Globe className="w-4 h-4 text-[#4F8CFF]" />URL Feature Breakdown
                    </h4>
                    <div className="grid grid-cols-2 gap-2 font-mono text-[10px]">
                      {([
                        ["Domain", urlResult.urlFeatures.domain],
                        ["TLD", urlResult.urlFeatures.tld],
                        ["Subdomains", String(urlResult.urlFeatures.subdomainCount)],
                        ["Path Depth", String(urlResult.urlFeatures.pathDepth)],
                        ["URL Length", `${urlResult.urlFeatures.urlLength} chars`],
                        ["IP Address", urlResult.urlFeatures.hasIPAddress ? "Detected ⚠" : "None"],
                        ["Encoded Chars", urlResult.urlFeatures.hasEncodedChars ? "Yes ⚠" : "No"],
                        ["Custom Port", urlResult.urlFeatures.hasPort ? "Yes ⚠" : "No"],
                      ] as [string, string][]).map(([k, v]) => (
                        <div key={k} className="p-2 bg-[#F8F7F4] rounded-lg border-2 border-black">
                          <span className="text-slate-500 font-bold">{k}: </span>
                          <span className="text-slate-900 font-black">{v}</span>
                        </div>
                      ))}
                    </div>
                    {urlResult.urlFeatures.suspiciousKeywords.length > 0 && (
                      <div className="p-2 bg-rose-50 border-2 border-black rounded-lg text-[10px] font-mono">
                        <span className="text-rose-700 font-black">Suspicious Keywords: </span>
                        <span className="text-rose-900 font-bold">{urlResult.urlFeatures.suspiciousKeywords.join(", ")}</span>
                      </div>
                    )}
                  </div>
                  <div className="space-y-1.5">
                    <h4 className="text-xs font-extrabold text-slate-800 flex items-center gap-1.5">
                      <FileText className="w-4 h-4 text-[#4F8CFF]" />AI Security Evaluation
                    </h4>
                    <p className="text-xs text-slate-900 font-semibold bg-[#F8F7F4] p-3 rounded-lg border-2 border-black leading-relaxed font-mono">{urlResult.explanation}</p>
                  </div>
                  {urlResult.riskFactors?.length > 0 && (
                    <div className="space-y-1.5">
                      <h4 className="text-xs font-extrabold text-rose-700 flex items-center gap-1.5"><AlertTriangle className="w-4 h-4" />Indicators Flagged</h4>
                      <ul className="text-[11px] space-y-1.5 bg-[#F8F7F4] p-3 rounded-lg border-2 border-black font-semibold">
                        {urlResult.riskFactors.map((f, i) => (
                          <li key={i} className="flex items-start gap-2 font-mono">
                            <span className="text-rose-600 font-black shrink-0">•</span><span>{f}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div className="p-3.5 bg-emerald-50 border-2 border-black rounded-lg space-y-1 shadow-[2px_2px_0px_0px_rgba(0,0,0,1)]">
                    <span className="text-[10px] font-mono font-black uppercase tracking-widest text-emerald-800">Action Recommended:</span>
                    <p className="text-xs text-emerald-950 mt-0.5 font-extrabold flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-700 stroke-[2.5]" />{urlResult.recommendedAction}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* SMS MODE */}
        {activeMode === "sms" && (
          <div className="grid md:grid-cols-2 gap-8 items-start">
            <form onSubmit={handleSMSScan} className="bg-white rounded-xl border-4 border-black p-6 space-y-4 shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
              <h3 className="font-display text-base font-black text-slate-950 border-b-2 border-black pb-2">Submit Suspicious SMS</h3>
              {smsError && (
                <div className="p-3 bg-red-100 border-2 border-black text-red-950 text-xs font-bold rounded-lg flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-red-700" />{smsError}
                </div>
              )}
              <div className="space-y-4 text-xs">
                <div>
                  <label className="block text-slate-800 font-mono font-bold uppercase tracking-wider mb-1.5">Sender Number / Name</label>
                  <input type="text" required placeholder="e.g. +1-800-555-0199 or HDFC-BANK"
                    value={smsSender} onChange={(e) => setSmsSender(e.target.value)}
                    className="w-full px-4 py-2.5 bg-white border-2 border-black rounded-lg text-slate-900 font-bold focus:outline-none focus:ring-2 focus:ring-[#4F8CFF] shadow-[2px_2px_0px_0px_rgba(0,0,0,1)]" />
                </div>
                <div>
                  <label className="block text-slate-800 font-mono font-bold uppercase tracking-wider mb-1.5">SMS Message Content</label>
                  <textarea required rows={8} placeholder="Paste the SMS message text here..."
                    value={smsContent} onChange={(e) => setSmsContent(e.target.value)}
                    className="w-full px-4 py-2.5 bg-white border-2 border-black rounded-lg text-slate-900 font-bold focus:outline-none focus:ring-2 focus:ring-[#4F8CFF] shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] font-mono resize-none leading-relaxed" />
                </div>
              </div>
              <div className="flex gap-2">
                <button type="button" onClick={() => { setSmsSender("+1-800-555-0199"); setSmsContent("URGENT: Your bank account has been locked. Click to restore: http://secure-bank-verify.xyz/unlock?id=9182"); }}
                  className="px-3.5 py-2 bg-[#FFEED4] border-2 border-black text-rose-950 text-xs font-extrabold rounded-lg shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] hover:bg-[#ffdcb0] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] transition-all cursor-pointer">
                  Load Phishing SMS
                </button>
                <button type="button" onClick={() => { setSmsSender("+91-98765-43210"); setSmsContent("Hi! Confirming our meeting tomorrow at 10 AM. Let me know if you need to reschedule. - Priya"); }}
                  className="px-3.5 py-2 bg-emerald-100 border-2 border-black text-emerald-950 text-xs font-extrabold rounded-lg shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] hover:bg-emerald-200 hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] transition-all cursor-pointer">
                  Load Safe SMS
                </button>
              </div>
              <button id="submit-sms-scan-btn" type="submit" disabled={smsLoading}
                className={`w-full py-3.5 rounded-lg text-sm font-extrabold transition-all border-2 border-black shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_0px_rgba(0,0,0,1)] active:translate-x-0 active:translate-y-0 cursor-pointer ${
                  smsLoading ? "bg-slate-200 text-slate-500 cursor-not-allowed shadow-none hover:translate-x-0 hover:translate-y-0" : "bg-[#4F8CFF] hover:bg-[#3b7ae6] text-white"
                }`}>
                {smsLoading ? "Analysing SMS..." : "Scan SMS Message"}
              </button>
            </form>

            <div className="space-y-6">
              {!smsResult && !smsLoading && (
                <div className="p-12 text-center rounded-xl border-4 border-dashed border-black bg-white/45 flex flex-col items-center justify-center min-h-[300px]">
                  <MessageSquare className="w-12 h-12 text-slate-400 mb-4 stroke-[1.5]" />
                  <h4 className="font-display font-black text-base text-slate-950 mb-1">SMS Analyser Idle</h4>
                  <p className="text-xs text-slate-700 font-bold max-w-xs leading-relaxed">
                    Paste an SMS you received. Gemini will check for smishing patterns, fake sender IDs and malicious embedded links.
                  </p>
                </div>
              )}
              {smsLoading && (
                <div className="p-12 text-center rounded-xl border-4 border-black bg-white flex flex-col items-center justify-center space-y-4 min-h-[300px] shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
                  <div className="w-10 h-10 rounded-lg border-4 border-black bg-white shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] flex items-center justify-center animate-spin">
                    <div className="w-3.5 h-3.5 bg-[#4F8CFF] rounded-sm" />
                  </div>
                  <h4 className="font-display font-black text-xs text-[#4F8CFF] tracking-widest uppercase">EVALUATING SMS WITH GEMINI...</h4>
                </div>
              )}
              {smsResult && (
                <div id="sms-scan-result" className="p-6 bg-white rounded-xl border-4 border-black space-y-5 text-left shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
                  <div>
                    <div className="flex items-center justify-between border-b-2 border-black pb-2">
                      <span className="text-[10px] font-mono font-black uppercase tracking-wider">SMS AUDIT REPORT</span>
                      <span className="px-2.5 py-1.5 rounded-md text-[10px] font-mono font-black bg-[#FFEED4] border-2 border-black shadow-[1.5px_1.5px_0px_0px_rgba(0,0,0,1)]">
                        Confidence {smsResult.confidenceScore}%
                      </span>
                    </div>
                    <h3 className="font-display font-black text-base mt-3 text-slate-950 flex flex-wrap items-center gap-1.5">
                      Classification: <span className="text-[#4F8CFF] bg-[#4F8CFF]/5 border border-[#4F8CFF] px-2 py-0.5 rounded">{smsResult.classification}</span>
                    </h3>
                  </div>
                  <div className="grid grid-cols-3 gap-3 font-mono text-[10px]">
                    <div className="p-2.5 bg-[#F8F7F4] rounded-lg border-2 border-black shadow-[1.5px_1.5px_0px_0px_rgba(0,0,0,1)]">
                      <div className="text-slate-600 font-bold">Phishing</div>
                      <div className="text-sm font-black text-rose-600 mt-1">{smsResult.phishingScore}%</div>
                    </div>
                    <div className="p-2.5 bg-[#F8F7F4] rounded-lg border-2 border-black shadow-[1.5px_1.5px_0px_0px_rgba(0,0,0,1)]">
                      <div className="text-slate-600 font-bold">Spam Score</div>
                      <div className="text-sm font-black text-[#4F8CFF] mt-1">{smsResult.spamScore}%</div>
                    </div>
                    <div className="p-2.5 bg-[#F8F7F4] rounded-lg border-2 border-black shadow-[1.5px_1.5px_0px_0px_rgba(0,0,0,1)]">
                      <div className="text-slate-600 font-bold">Risk Level</div>
                      <div className="text-xs font-black text-[#e49b0f] mt-1 uppercase">{smsResult.riskLevel}</div>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <h4 className="text-xs font-extrabold text-slate-800 flex items-center gap-1.5"><FileText className="w-4 h-4 text-[#4F8CFF]" />AI Security Evaluation</h4>
                    <p className="text-xs text-slate-900 font-semibold bg-[#F8F7F4] p-3 rounded-lg border-2 border-black leading-relaxed font-mono">{smsResult.explanation}</p>
                  </div>
                  {smsResult.riskFactors?.length > 0 && (
                    <div className="space-y-1.5">
                      <h4 className="text-xs font-extrabold text-rose-700 flex items-center gap-1.5"><AlertTriangle className="w-4 h-4" />Indicators Flagged</h4>
                      <ul className="text-[11px] space-y-1.5 bg-[#F8F7F4] p-3 rounded-lg border-2 border-black font-semibold">
                        {smsResult.riskFactors.map((f, i) => (
                          <li key={i} className="flex items-start gap-2 font-mono">
                            <span className="text-rose-600 font-black shrink-0">•</span><span>{f}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div className="p-3.5 bg-emerald-50 border-2 border-black rounded-lg space-y-1 shadow-[2px_2px_0px_0px_rgba(0,0,0,1)]">
                    <span className="text-[10px] font-mono font-black uppercase tracking-widest text-emerald-800">Action Recommended:</span>
                    <p className="text-xs text-emerald-950 mt-0.5 font-extrabold flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-700 stroke-[2.5]" />{smsResult.recommendedAction}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
