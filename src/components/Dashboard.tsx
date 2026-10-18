import React, { useState, useEffect } from "react";
import { 
  Shield, Mail, Settings, RefreshCw, LogOut, CheckCircle, AlertTriangle, 
  Trash2, Plus, Play, Info, AlertOctagon, Layers, ArrowLeft, ArrowRight, Activity, Zap, FileText, ToggleLeft, ToggleRight
} from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from "recharts";
import { UserProfile, ScannedEmail, AutomationRule, ActivityLog } from "../types.ts";

interface DashboardProps {
  user: { id: string };
  onLogout: () => void;
  userProfile: UserProfile | null;
  onRefreshProfile: () => void;
  onPageChange: (page: string) => void;
}

export default function Dashboard({ 
  user, onLogout, userProfile, onRefreshProfile, onPageChange 
}: DashboardProps) {
  const [emails, setEmails] = useState<ScannedEmail[]>([]);
  const [rules, setRules] = useState<AutomationRule[]>([]);
  const [logs, setLogs] = useState<ActivityLog[]>([]);
  
  // UI and syncing states
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [selectedMail, setSelectedMail] = useState<ScannedEmail | null>(null);
  const [activeTab, setActiveTab] = useState<"inbox" | "rules" | "logs">("inbox");

  // Rule creator form states
  const [ruleType, setRuleType] = useState<AutomationRule["emailType"]>("newsletter");
  const [ruleAction, setRuleAction] = useState<AutomationRule["action"]>("label");
  const [ruleLabelName, setRuleLabelName] = useState("");
  const [isAddingRule, setIsAddingRule] = useState(false);

  // Settings states
  const [protectionLevel, setProtectionLevel] = useState<UserProfile["protectionLevel"]>(
    userProfile?.protectionLevel || "balanced"
  );
  const [subscription, setSubscription] = useState<UserProfile["subscription"]>(
    userProfile?.subscription || "free"
  );
  const [isSavingSettings, setIsSavingSettings] = useState(false);

  // Sync state with local state changes in parent profile
  useEffect(() => {
    if (userProfile) {
      setProtectionLevel(userProfile.protectionLevel);
      setSubscription(userProfile.subscription);
    }
  }, [userProfile]);

  const [gmailConnected, setGmailConnected] = useState(true);

  const api = async (path: string, init?: RequestInit) => {
    const res = await fetch(`/api${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `Request failed (${res.status})`);
    }
    return res.json();
  };

  const loadEmails = () => api("/emails").then(setEmails).catch((e) => console.error("Load emails failed:", e));
  const loadRules = () => api("/rules").then(setRules).catch((e) => console.error("Load rules failed:", e));
  const loadLogs = () => api("/activity").then(setLogs).catch((e) => console.error("Load activity failed:", e));
  const loadAll = () => Promise.all([loadEmails(), loadRules(), loadLogs()]);

  useEffect(() => {
    loadAll();
    api("/gmail/status").then((r) => setGmailConnected(r.connected)).catch(() => {});
  }, [user.id]);

  // Call the backend endpoint to sync and scan latest emails with Gemini AI securely
  const handleSyncGmail = async () => {
    setIsSyncing(true);
    setSyncError(null);

    try {
      await api("/gmail/sync", { method: "POST" });
      await loadAll();
    } catch (err: any) {
      console.error("Sync error:", err);
      setSyncError(err.message || "Threat scanning interface is currently busy.");
    } finally {
      setIsSyncing(false);
    }
  };

  // Rule operations code
  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api("/rules", {
        method: "POST",
        body: JSON.stringify({ emailType: ruleType, action: ruleAction, labelName: ruleLabelName }),
      });
      setRuleLabelName("");
      setIsAddingRule(false);
      await Promise.all([loadRules(), loadLogs()]);
    } catch (err) {
      console.error("Add rule error:", err);
    }
  };

  const handleToggleRuleStatus = async (ruleId: string, currentStatus: boolean) => {
    try {
      await api(`/rules/${ruleId}`, { method: "PATCH", body: JSON.stringify({ active: !currentStatus }) });
      await loadRules();
    } catch (err) {
      console.error("Toggle rule failed:", err);
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    try {
      await api(`/rules/${ruleId}`, { method: "DELETE" });
      await loadRules();
    } catch (err) {
      console.error("Delete rule failed:", err);
    }
  };

  // Profile preferences settings update
  const handleUpdateSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingSettings(true);
    try {
      await api("/settings", { method: "PATCH", body: JSON.stringify({ protectionLevel, subscription }) });
      onRefreshProfile();
      await loadLogs();
    } catch (err) {
      console.error("Settings update failed:", err);
    } finally {
      setIsSavingSettings(false);
    }
  };

  // Recharts Data preparation
  // 1. Classification distribution data
  const categoryCounter = emails.reduce((acc: Record<string, number>, curr) => {
    const cls = curr.classification || "Personal";
    acc[cls] = (acc[cls] || 0) + 1;
    return acc;
  }, {});

  const pieData = Object.entries(categoryCounter).map(([name, value]) => ({ name, value }));
  const COLORS = [
    "#3b82f6", "#10b981", "#ef4444", "#f59e0b", "#8b5cf6", 
    "#ec4899", "#14b8a6", "#6366f1", "#f97316", "#06b6d4"
  ];

  // 2. Risk over time metrics
  const sortedEmailsForTime = [...emails].reverse();
  const timeChartData = sortedEmailsForTime.slice(-15).map((mail, idx) => ({
    name: mail.date ? mail.date.substring(5, 10) : `Item ${idx + 1}`,
    threat: Math.max(mail.threatScore, mail.phishingScore, mail.spamScore)
  }));

  // Statistics calculation helpers
  const totalScannedCount = emails.length;
  const criticalThreatsCount = emails.filter(m => m.riskLevel === "Critical" || m.riskLevel === "High Risk").length;
  const safeCount = emails.filter(m => m.riskLevel === "Safe").length;
  const overallSecurityIndex = totalScannedCount > 0 
    ? Math.round(100 - (emails.reduce((acc, c) => acc + c.threatScore, 0) / totalScannedCount) * 0.45)
    : 100;

  return (
    <div className="min-h-screen bg-[#F8F7F4] text-slate-900 flex flex-col md:flex-row font-sans selection:bg-[#4F8CFF] relative">

      {/* Dynamic Desktop Sidebar */}
      <aside className="w-full md:w-64 bg-white border-b-4 md:border-b-0 md:border-r-4 border-black p-5 shrink-0 flex flex-col justify-between relative z-15">
        <div className="space-y-8">
          {/* Branded Title block */}
          <div className="flex items-center gap-3">
            <div className="p-1.5 bg-[#4F8CFF] border-2 border-black rounded-lg">
              <Shield className="w-5 h-5 text-white stroke-[2.5]" />
            </div>
            <span className="font-display font-black text-lg tracking-tight text-slate-950">
              SecureBox <span className="text-[#4F8CFF] font-black">AI</span>
            </span>
          </div>

          {/* User Badge Profile */}
          {userProfile && (
            <div className="p-3.5 bg-[#FFEED4] border-2 border-black rounded-xl flex items-center gap-3 shadow-[3px_3px_0px_0px_rgba(0,0,0,1)]">
              <img 
                src={userProfile.photoURL || `https://api.dicebear.com/7.x/bottts/svg?seed=${userProfile.uid}`} 
                alt="Avatar" 
                className="w-10 h-10 rounded-lg bg-white border-2 border-black"
                referrerPolicy="no-referrer"
              />
              <div className="overflow-hidden">
                <div className="text-xs font-black text-slate-950 truncate">{userProfile.displayName || "Secure Admin"}</div>
                <div className="text-[10px] text-slate-700 font-bold font-mono truncate">{userProfile.email}</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  <span className="text-[8px] font-mono font-black uppercase tracking-wide bg-white border border-black px-1.5 py-0.5 rounded text-slate-900">
                    {userProfile.protectionLevel}
                  </span>
                  <span className="text-[8px] font-mono font-black uppercase tracking-wide bg-[#4F8CFF] border border-black px-1.5 py-0.5 rounded text-white">
                    {userProfile.subscription}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Action Navigation Panels */}
          <nav className="flex flex-col gap-2">
            <button
              onClick={() => setActiveTab("inbox")}
              className={`w-full py-3 px-4 rounded-xl text-xs font-display font-black text-left flex items-center justify-between border-2 border-black transition-all cursor-pointer ${
                activeTab === "inbox" 
                  ? "bg-[#4F8CFF] text-white translate-x-[-1px] translate-y-[-1px]" 
                  : "bg-white text-slate-800 hover:bg-slate-50 active:translate-x-0 active:translate-y-0"
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Mail className="w-4 h-4 stroke-[2.5]" />
                Gmail Scans
              </span>
              <span className="text-[10px] bg-black text-white px-2 py-0.5 rounded font-black font-mono border border-black shadow-[1px_1px_0px_0px_rgba(255,255,255,1)]">{emails.length}</span>
            </button>

            <button
              onClick={() => setActiveTab("rules")}
              className={`w-full py-3 px-4 rounded-xl text-xs font-display font-black text-left flex items-center justify-between border-2 border-black transition-all cursor-pointer ${
                activeTab === "rules" 
                  ? "bg-[#4F8CFF] text-white translate-x-[-1px] translate-y-[-1px]" 
                  : "bg-white text-slate-800 hover:bg-slate-50 active:translate-x-0 active:translate-y-0"
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Layers className="w-4 h-4 stroke-[2.5]" />
                Automation Rules
              </span>
              <span className="text-[10px] bg-black text-white px-2 py-0.5 rounded font-black font-mono border border-black shadow-[1px_1px_0px_0px_rgba(255,255,255,1)]">{rules.length}</span>
            </button>

            <button
              onClick={() => setActiveTab("logs")}
              className={`w-full py-3 px-4 rounded-xl text-xs font-display font-black text-left flex items-center justify-between border-2 border-black transition-all cursor-pointer ${
                activeTab === "logs" 
                  ? "bg-[#4F8CFF] text-white translate-x-[-1px] translate-y-[-1px]" 
                  : "bg-white text-slate-800 hover:bg-slate-50 active:translate-x-0 active:translate-y-0"
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Activity className="w-4 h-4 stroke-[2.5]" />
                Activity Trails
              </span>
            </button>
            
            <button
              onClick={() => onPageChange("sandbox")}
              className="mt-6 w-full py-3 px-4 bg-[#FFEED4] hover:bg-[#ffdcb0] text-slate-900 rounded-xl text-xs font-display font-black text-left flex items-center gap-2.5 border-2 border-black shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[4.5px_4.5px_0px_0px_rgba(0,0,0,1)] active:translate-x-0 active:translate-y-0 transition-all cursor-pointer"
            >
              <Info className="w-4.5 h-4.5 text-[#4F8CFF] stroke-[2.5]" />
              Manual Cold Sandbox
            </button>
          </nav>
        </div>

        {/* Logout Trigger button */}
        <div className="pt-6 border-t border-slate-200 mt-8 md:mt-0">
          <button
            onClick={onLogout}
            className="w-full py-2.5 px-4 text-xs font-display font-black text-rose-700 bg-white hover:bg-rose-50 hover:text-rose-950 border-2 border-black rounded-lg flex items-center justify-center gap-2 hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[3.5px_3.5px_0px_0px_rgba(0,0,0,1)] active:translate-x-0 active:translate-y-0 transition-all cursor-pointer"
          >
            <LogOut className="w-4 h-4 stroke-[2.5]" />
            Sign Out Securely
          </button>
        </div>
      </aside>

      {/* Main Panel Workspace */}
      <main className="flex-1 p-6 md:p-8 space-y-8 overflow-y-auto max-w-7xl mx-auto w-full relative z-10 text-left">
        {/* Banner Headers containing Sync triggers */}
        <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6 pb-6 border-b border-slate-200">
          <div>
            <h1 className="font-display font-black text-2xl md:text-3.5xl tracking-tight text-slate-950">Security Overview</h1>
          </div>

          <div className="flex items-center gap-3">
            <button
              id="sync-logs-btn"
              onClick={handleSyncGmail}
              disabled={isSyncing}
              className={`px-5 py-3 rounded-lg text-xs font-display font-black border-2 border-black transition-all flex items-center gap-2 shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_0px_rgba(0,0,0,1)] active:translate-x-0 active:translate-y-0 ${
                isSyncing 
                  ? "bg-slate-200 text-slate-500 cursor-not-allowed shadow-none hover:translate-x-0 hover:translate-y-0" 
                  : "bg-[#4F8CFF] text-white cursor-pointer"
              }`}
            >
              <RefreshCw className={`w-4.5 h-4.5 stroke-[2.5] ${isSyncing ? "animate-spin" : ""}`} />
              {isSyncing ? "Scanning Inbox..." : "Sync & Scan Gmail"}
            </button>
          </div>
        </header>

        {!gmailConnected && (
          <div className="p-4 bg-[#FFEED4] border-2 border-black text-slate-950 text-xs font-bold rounded-lg shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] flex items-start gap-3">
            <Info className="w-5 h-5 shrink-0 mt-0.5 text-[#4F8CFF] stroke-[2.5]" />
            <div>
              <p className="font-bold text-slate-900">Demo mode: showing simulated emails analyzed by Gemini. Sign in with Google to scan your real inbox.</p>
            </div>
          </div>
        )}

        {syncError && (
          <div className="p-4 bg-red-105 border-2 border-black text-red-950 text-xs font-bold rounded-lg shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 shrink-0 text-red-700" />
            <span>
              <strong>Sync failed:</strong> {syncError}. 
            </span>
          </div>
        )}

        {/* Analytics Numeric Counters Block */}
        <section className="grid grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6">
          <div className="p-5 bg-white border border-slate-200 rounded-xl">
            <div className="flex items-center justify-between text-slate-500 mb-3 font-mono font-bold text-[10px]">
              <span>HEALTH INDEX</span>
              <Shield className="w-4 h-4 text-emerald-600 stroke-[2.5]" />
            </div>
            <div className="text-3xl font-display font-black text-emerald-600">
              {overallSecurityIndex}%
            </div>
          </div>

          <div className="p-5 bg-white border border-slate-200 rounded-xl">
            <div className="flex items-center justify-between text-slate-500 mb-3 font-mono font-bold text-[10px]">
              <span>TOTAL SCANNED</span>
              <Mail className="w-4 h-4 text-[#4F8CFF] stroke-[2.5]" />
            </div>
            <div className="text-3xl font-display font-black text-[#4F8CFF]">
              {totalScannedCount}
            </div>
          </div>

          <div className="p-5 bg-white border border-slate-200 rounded-xl">
            <div className="flex items-center justify-between text-slate-500 mb-3 font-mono font-bold text-[10px]">
              <span>HIGH RISK EMAILS</span>
              <AlertTriangle className="w-4 h-4 text-rose-600 stroke-[2.5]" />
            </div>
            <div className={`text-3xl font-display font-black ${criticalThreatsCount > 0 ? "text-rose-600" : "text-slate-400"}`}>
              {criticalThreatsCount}
            </div>
          </div>

          <div className="p-5 bg-white border border-slate-200 rounded-xl">
            <div className="flex items-center justify-between text-slate-500 mb-3 font-mono font-bold text-[10px]">
              <span>AUTOMATIONS RUN</span>
              <Zap className="w-4 h-4 text-amber-600 stroke-[2.5]" />
            </div>
            <div className="text-3xl font-display font-black text-amber-600">
              {logs.filter(l => l.type === "rules").length}
            </div>
          </div>
        </section>

        {/* Visual Charts section */}
        {totalScannedCount > 0 && (
          <section className="grid lg:grid-cols-3 gap-6">
            {/* Risk Index Over Time Chart */}
            <div className="p-5 bg-white border border-slate-200 rounded-xl lg:col-span-2 space-y-4">
              <h3 className="font-display font-black text-xs tracking-wider text-slate-950 uppercase border-b border-slate-200 pb-2">Inbox Threat Timeline Profile</h3>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timeChartData}>
                    <defs>
                      <linearGradient id="colorThreat" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.15}/>
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="name" stroke="#000000" fontSize={9} fontWeight="bold" tickLine={false} />
                    <YAxis stroke="#000000" fontSize={9} fontWeight="bold" tickLine={false} domain={[0, 100]} />
                    <Tooltip contentStyle={{ backgroundColor: "#ffffff", border: "2px solid #000000", fontFamily: "monospace", fontSize: "11px", fontWeight: "bold" }} />
                    <Area type="monotone" dataKey="threat" stroke="#ef4444" strokeWidth={3} fillOpacity={1} fill="url(#colorThreat)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Classification category distribution */}
            <div className="p-5 bg-white border border-slate-200 rounded-xl space-y-4 flex flex-col justify-between">
              <h3 className="font-display font-black text-xs tracking-wider text-slate-950 uppercase border-b border-slate-200 pb-2 mr-1">Inbox Distribution Model</h3>
              <div className="h-44 flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={70}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} stroke="#000" strokeWidth={2} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: "#ffffff", border: "2px solid #000000", fontFamily: "monospace", fontSize: "11px", fontWeight: "bold" }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex flex-wrap justify-center gap-x-3 gap-y-1.5 text-[9px] text-slate-800 font-mono font-bold">
                {pieData.map((item, idx) => (
                  <span key={item.name} className="flex items-center gap-1 bg-[#F8F7F4] px-1.5 py-0.5 border border-black rounded">
                    <span className="w-2.5 h-2.5 rounded-sm border border-black shrink-0" style={{ backgroundColor: COLORS[idx % COLORS.length] }} />
                    {item.name} ({item.value})
                  </span>
                ))}
              </div>
            </div>
          </section>
        )}

        {/* Split Dynamic Tab Contents block */}
        <section className="grid lg:grid-cols-3 gap-8">
          
          {/* LEFT WIDE COLUMN FOR ACTIVE PANEL CONTENTS */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* INBOX MANAGEMENT PANEL */}
            {activeTab === "inbox" && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-display font-black text-lg text-slate-950">Scanned Inbox Items</h3>
                </div>

                {emails.length === 0 ? (
                  <div className="p-12 text-center rounded-xl border-2 border-dashed border-slate-300 bg-white/45 flex flex-col items-center justify-center">
                    <Mail className="w-12 h-12 text-slate-400 mb-4" />
                    <h4 className="font-display font-black text-sm text-slate-900 mb-1">Your inbox scans list is empty</h4>
                    <p className="text-xs text-slate-700 font-bold max-w-sm">
                      Press "Sync & Scan Gmail" at the top to import mock datasets or real-time authorized Gmail items.
                    </p>
                  </div>
                ) : (
                  <div id="scanned-emails-container" className="space-y-4">
                    {emails.map((mail) => {
                      const maxScore = Math.max(mail.threatScore, mail.phishingScore, mail.spamScore);
                      let riskColor = "bg-emerald-100 border border-emerald-300 text-emerald-950";
                      if (mail.riskLevel === "Low Risk") riskColor = "bg-blue-100 border border-blue-300 text-blue-950";
                      else if (mail.riskLevel === "Medium Risk") riskColor = "bg-amber-100 border border-amber-300 text-slate-950";
                      else if (mail.riskLevel === "High Risk" || mail.riskLevel === "Critical") riskColor = "bg-rose-100 border border-rose-300 text-rose-950";

                      return (
                        <div 
                           key={mail.id}
                           id={`email-item-${mail.id}`}
                           onClick={() => setSelectedMail(mail)}
                           className={`p-4 bg-white border border-slate-200 rounded-xl hover:border-black cursor-pointer transition-colors flex items-start gap-4 ${
                             selectedMail?.id === mail.id ? "bg-[#FFEED4] hover:bg-[#FFEED4]" : ""
                           }`}
                        >
                          {/* Threat Indicator Dot */}
                          <div className={`w-3.5 h-3.5 rounded-full shrink-0 font-bold border-2 border-black mt-1 ${
                            maxScore > 75 ? "bg-rose-500" : maxScore > 40 ? "bg-amber-400" : "bg-emerald-500"
                          }`} />

                          <div className="flex-1 min-w-0 space-y-2">
                            <div className="flex items-center justify-between gap-3">
                              <span className="text-xs font-black text-slate-950 truncate max-w-[200px]">{mail.from}</span>
                              <span className="text-[10px] text-slate-700 font-mono font-bold bg-[#F8F7F4] border border-black px-1.5 py-0.5 rounded shrink-0">
                                {mail.date ? mail.date.substring(0, 10) : "Today"}
                              </span>
                            </div>

                            <h4 className="text-xs font-extrabold text-slate-950 truncate font-mono">{mail.subject}</h4>
                            <p className="text-[11px] text-slate-800 font-semibold line-clamp-1 leading-relaxed">{mail.snippet}</p>

                            {/* Classification badging */}
                            <div className="flex flex-wrap items-center gap-2 pt-1">
                              <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-black border ${riskColor}`}>
                                {mail.riskLevel}
                              </span>
                              <span className="px-2 py-0.5 rounded bg-white border-2 border-black text-slate-900 text-[9px] font-mono font-black">
                                {mail.classification}
                              </span>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* AUTOMATION RULES CONFIGURATOR PANEL */}
            {activeTab === "rules" && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-display font-black text-lg text-slate-950">Dynamic Filter Automations</h3>
                    
                  </div>
                  <button
                    onClick={() => setIsAddingRule(!isAddingRule)}
                    className="px-4 py-2.5 bg-[#4F8CFF] hover:bg-[#3472e3] border-2 border-black rounded-lg text-xs font-display font-black text-white hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[3.5px_3.5px_0px_0px_rgba(0,0,0,1)] active:translate-x-0 active:translate-y-0 transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <Plus className="w-4 h-4 stroke-[2.5]" />
                    Create Custom Rule
                  </button>
                </div>

                {isAddingRule && (
                  <form onSubmit={handleAddRule} className="p-5 bg-white border border-slate-200 rounded-xl space-y-4">
                    <div className="grid sm:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-mono font-black uppercase tracking-wider text-slate-700 mb-1.5">Trigger Entity Classification</label>
                        <select
                          value={ruleType}
                          onChange={(e) => setRuleType(e.target.value as AutomationRule["emailType"])}
                          className="w-full px-3 py-2 bg-white border-2 border-black rounded-lg text-xs font-bold text-slate-900 focus:outline-none focus:ring-1 focus:ring-[#4F8CFF]"
                        >
                          <option value="newsletter">Newsletter</option>
                          <option value="promotion">Promotion (Marketing)</option>
                          <option value="cold_outreach">Cold Outreach</option>
                          <option value="high_risk">High Risk Warn</option>
                          <option value="phishing">Phishing Intent</option>
                          <option value="important">Important Priority</option>
                          <option value="work">Work/Jobs</option>
                        </select>
                      </div>

                      <div>
                        <label className="block text-xs font-mono font-black uppercase tracking-wider text-slate-700 mb-1.5">Organize Action</label>
                        <select
                          value={ruleAction}
                          onChange={(e) => setRuleAction(e.target.value as AutomationRule["action"])}
                          className="w-full px-3 py-2 bg-white border-2 border-black rounded-lg text-xs font-bold text-slate-900 focus:outline-none focus:ring-1 focus:ring-[#4F8CFF]"
                        >
                          <option value="label">Apply Custom Gmail Label</option>
                          <option value="archive">Archive (Remove Inbox)</option>
                          <option value="mark_read">Mark Message as Read</option>
                          <option value="move_trash">Move to Bin Trash</option>
                        </select>
                      </div>
                    </div>

                    {ruleAction === "label" && (
                      <div>
                        <label className="block text-xs font-mono font-black uppercase tracking-wider text-slate-700 mb-1.5">Custom Gmail Label Name</label>
                        <input
                          type="text"
                          required
                          value={ruleLabelName}
                          onChange={(e) => setRuleLabelName(e.target.value)}
                          placeholder="e.g. SecureBox/ColdMarketing"
                          className="w-full px-4 py-2.5 bg-white border-2 border-black rounded-lg text-xs font-bold focus:outline-none focus:ring-2 focus:ring-[#4F8CFF] text-slate-905"
                        />
                      </div>
                    )}

                    <div className="flex justify-end gap-3 pt-2">
                      <button
                        type="button"
                        onClick={() => setIsAddingRule(false)}
                        className="px-4 py-2 border-2 border-black rounded-lg text-xs text-slate-800 font-bold hover:bg-slate-50 cursor-pointer"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        className="px-5 py-2 rounded-lg text-xs font-display font-black bg-[#4F8CFF] hover:bg-[#3472e3] border-2 border-black text-white hover:-translate-x-0.5 hover:-translate-y-0.5 active:translate-x-0 active:translate-y-0 cursor-pointer"
                      >
                        Activate Rule
                      </button>
                    </div>
                  </form>
                )}

                <div className="space-y-4">
                  {rules.length === 0 ? (
                    <div className="p-8 text-center rounded-xl bg-white border-2 border-dashed border-slate-300 text-slate-755 text-xs font-bold">
                      No active security filters configured. Click "Create Custom Rule" above to initiate automations.
                    </div>
                  ) : (
                    rules.map((rule) => (
                      <div 
                        key={rule.id}
                        className="p-4 bg-white border border-slate-200 rounded-xl flex items-center justify-between gap-4"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-black text-slate-950">
                              IF Classified as <span className="text-[#4F8CFF] font-mono capitalize">"{rule.emailType}"</span>
                            </span>
                            {!rule.active && (
                              <span className="text-[9px] bg-slate-200 text-slate-705 font-bold px-2 py-0.5 rounded border border-black uppercase tracking-wider">Deactivated</span>
                            )}
                          </div>
                          
                          <div className="text-[11px] text-slate-700 mt-1.5 flex items-center gap-1.5">
                            <span className="font-mono bg-[#FFEED4] px-1.5 py-0.5 rounded border border-black text-slate-950 uppercase tracking-wider font-black">{rule.action}</span>
                            {rule.action === "label" && (
                              <span className="font-semibold text-slate-800">Apply Filter Label Name: <strong className="font-mono text-slate-950 font-black">"{rule.labelName}"</strong></span>
                            )}
                          </div>
                        </div>

                        <div className="flex items-center gap-3">
                          <button
                            onClick={() => handleToggleRuleStatus(rule.id, rule.active)}
                            className="text-slate-800 hover:text-[#4F8CFF] transition-colors cursor-pointer"
                          >
                            {rule.active ? (
                              <ToggleRight className="w-8 h-8 text-[#4F8CFF]" />
                            ) : (
                              <ToggleLeft className="w-8 h-8 text-slate-400" />
                            )}
                          </button>
                          
                          <button
                            onClick={() => handleDeleteRule(rule.id)}
                            className="p-2 text-slate-800 hover:text-rose-600 rounded-lg bg-white border-2 border-black hover:-translate-x-0.5 hover:-translate-y-0.5 active:translate-x-0 active:translate-y-0 transition-all cursor-pointer"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* SECURITY AUDIT LOGS TRAIL PANEL */}
            {activeTab === "logs" && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-display font-black text-lg text-slate-950">Inbox Security Audit Trail</h3>
                  <span className="px-2.5 py-1 bg-emerald-100 border border-emerald-300 rounded text-[9px] font-mono text-emerald-950 font-black uppercase tracking-wider">Live</span>
                </div>

                <div className="bg-white rounded-xl border border-slate-200 p-5 h-[420px] overflow-y-auto space-y-3.5 font-mono text-xs">
                  {logs.length === 0 ? (
                    <p className="text-slate-500 text-center py-10">// Dynamic audits will show up on email scans.</p>
                  ) : (
                    logs.map((log) => {
                      let typeBadge = "text-blue-700 bg-blue-50";
                      if (log.type === "rules") typeBadge = "text-amber-700 bg-amber-50";
                      else if (log.type === "security") typeBadge = "text-rose-700 bg-rose-50";
                      else if (log.type === "system") typeBadge = "text-purple-700 bg-purple-50";

                      return (
                        <div key={log.id} className="border-b border-slate-200 pb-3 last:border-0 leading-relaxed text-slate-900">
                          <div className="flex items-center justify-between text-[10px] text-slate-550 mb-1">
                            <span className={`font-black px-1.5 py-0.5 rounded border border-black uppercase text-[9px] ${typeBadge}`}>[{log.type}]</span>
                            <span className="font-bold text-slate-600">{log.timestamp ? log.timestamp.replace("T", " ").substring(0, 19) : ""}</span>
                          </div>
                          <p className="text-slate-950 font-bold mt-1 max-w-full overflow-hidden truncate whitespace-normal">{log.action}</p>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            )}
          </div>

          {/* RIGHT PANELS WORKSPACE (SETTINGS AND DRAWER INFORMATION) */}
          <div className="space-y-8">
            
            {/* POLICY SETTINGS */}
            <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-5 text-left">
              <h3 className="font-display font-black text-base text-slate-950 border-b border-slate-200 pb-2">Security Guard Settings</h3>
              
              <form onSubmit={handleUpdateSettings} className="space-y-4">
                <div>
                  <label className="block text-[10px] font-mono font-black uppercase tracking-wider text-slate-700 mb-1.5">
                    Protection Level
                  </label>
                  <select
                    value={protectionLevel}
                    onChange={(e) => setProtectionLevel(e.target.value as UserProfile["protectionLevel"])}
                    className="w-full px-3 py-2 bg-white border-2 border-black rounded-lg text-xs font-bold text-slate-900 focus:outline-none focus:ring-1 focus:ring-[#4F8CFF]"
                  >
                    <option value="relaxed">Relaxed Mode (Lower false alarms)</option>
                    <option value="balanced">Balanced Mode (Recommendation)</option>
                    <option value="strict">Strict Mode (Deep suspicious flags)</option>
                    <option value="enterprise">Enterprise Shield (Strict lockdowns)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[10px] font-mono font-black uppercase tracking-wider text-slate-700 mb-1.5">
                    Access tier Plan
                  </label>
                  <select
                    value={subscription}
                    onChange={(e) => setSubscription(e.target.value as UserProfile["subscription"])}
                    className="w-full px-3 py-2 bg-white border-2 border-black rounded-lg text-xs font-bold text-slate-900 focus:outline-none focus:ring-1 focus:ring-[#4F8CFF]"
                  >
                    <option value="free">Free account</option>
                    <option value="superman">Superman Edition ($20/mo)</option>
                    <option value="batman">Batman Theme Edition ($35/mo)</option>
                  </select>
                </div>

                <button
                  type="submit"
                  disabled={isSavingSettings}
                  className="w-full py-3 rounded-lg bg-[#4F8CFF] hover:bg-[#3472e3] font-display font-black text-xs text-white border-2 border-black hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[4px_4px_0px_0px_rgba(0,0,0,1)] active:translate-x-0 active:translate-y-0 transition-all cursor-pointer"
                >
                  {isSavingSettings ? "Saving Settings..." : "Save Security Profiles"}
                </button>
              </form>
            </div>

            {/* SECURITY THREAT DEEP AUDIT DRAWER */}
            {selectedMail && (
              <div id="email-detail-card" className="p-5 rounded-xl bg-white border border-slate-200 text-left relative space-y-4 animate-fade-in">
                <div className="absolute top-3 right-3 flex gap-2">
                  <button 
                    onClick={() => setSelectedMail(null)} 
                    className="p-1 px-2.5 text-[10px] bg-white border-2 border-black text-slate-900 rounded-lg font-black hover:bg-slate-50 cursor-pointer active:translate-x-0.5 active:translate-y-0.5"
                  >
                    Close
                  </button>
                </div>

                <div className="space-y-4">
                  <div className="pt-2">
                    <span className="text-[9px] font-mono font-black text-rose-700 bg-rose-50 border border-black px-2 py-0.5 rounded">THREAT INTELLIGENCE AUDIT</span>
                    <h3 className="font-display text-base font-black mt-3 text-slate-950">{selectedMail.subject}</h3>
                    <p className="text-[10px] text-slate-800 font-bold font-mono mt-1 leading-relaxed truncate">From: {selectedMail.from}</p>
                  </div>

                  <div className="border-t border-slate-200 pt-1" />

                  {/* Classification stats */}
                  <div className="grid grid-cols-2 gap-3 font-mono text-[10px]">
                    <div className="p-2 sm:p-2.5 bg-[#F8F7F4] rounded-lg border border-slate-200">
                      <div className="text-slate-600 font-bold">Phishing prob</div>
                      <div className="text-sm font-black text-rose-600 mt-1">{selectedMail.phishingScore}%</div>
                    </div>
                    <div className="p-2 sm:p-2.5 bg-[#F8F7F4] rounded-lg border border-slate-200">
                      <div className="text-slate-600 font-bold">Spam prob</div>
                      <div className="text-sm font-black text-[#4F8CFF] mt-1">{selectedMail.spamScore}%</div>
                    </div>
                    <div className="p-2 sm:p-2.5 bg-[#F8F7F4] rounded-lg border border-slate-200">
                      <div className="text-slate-600 font-bold">Threat level</div>
                      <div className="text-sm font-black text-amber-600 mt-1">{selectedMail.threatScore}%</div>
                    </div>
                    <div className="p-2 sm:p-2.5 bg-[#F8F7F4] rounded-lg border border-slate-200">
                      <div className="text-slate-600 font-bold">Classification</div>
                      <div className="text-sm font-black text-purple-650 mt-1">{selectedMail.classification}</div>
                    </div>
                  </div>

                  {/* Threat assessment explanation */}
                  <div className="space-y-1.5">
                    <h4 className="text-xs font-black text-slate-850 flex items-center gap-1.5">
                      <FileText className="w-3.5 h-3.5 text-[#4F8CFF] stroke-[2.5]" />
                      AI Threat Explanation
                    </h4>
                    <p className="text-xs text-slate-900 leading-relaxed font-bold bg-[#F8F7F4] p-3 rounded-lg border border-slate-200 font-mono">
                      {selectedMail.explanation}
                    </p>
                  </div>

                  {/* Flags detected */}
                  {selectedMail.riskFactors && selectedMail.riskFactors.length > 0 && (
                    <div className="space-y-1.5">
                      <h4 className="text-xs font-black text-rose-700 flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Identified Risk Factors
                      </h4>
                      <ul className="text-[10px] text-slate-900 leading-normal space-y-1 bg-[#F8F7F4] p-3 rounded-lg border border-slate-200">
                        {selectedMail.riskFactors.map((factor, i) => (
                          <li key={i} className="flex items-start gap-1 font-mono font-bold">
                            <span className="text-rose-600 font-black shrink-0 select-none">•</span>
                            {factor}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Immediate Recommended Action */}
                  <div className="p-3 bg-emerald-50 border-2 border-black rounded-lg space-y-1">
                    <span className="text-[9px] font-mono font-black uppercase tracking-widest text-emerald-800">RECOMMENDED INTERVENTION:</span>
                    <p className="text-xs text-emerald-950 mt-0.5 font-black">
                      {selectedMail.recommendedAction}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
