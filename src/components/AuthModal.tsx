import React, { useEffect, useState } from "react";
import { Shield, X } from "lucide-react";
import { authClient } from "../lib/auth-client.ts";

interface AuthModalProps {
  onClose: () => void;
}

export default function AuthModal({ onClose }: AuthModalProps) {
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [googleEnabled, setGoogleEnabled] = useState(false);

  useEffect(() => {
    fetch("/api/config")
      .then((r) => r.json())
      .then((c) => setGoogleEnabled(Boolean(c.googleEnabled)))
      .catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const { error } =
      mode === "signup"
        ? await authClient.signUp.email({ name: name || email.split("@")[0], email, password })
        : await authClient.signIn.email({ email, password });
    setBusy(false);
    if (error) setError(error.message || "Something went wrong. Please try again.");
    else onClose();
  };

  const handleGoogle = async () => {
    setError(null);
    const { error } = await authClient.signIn.social({ provider: "google", callbackURL: "/" });
    if (error) setError(error.message || "Google sign-in failed.");
  };

  const input =
    "w-full px-4 py-2.5 bg-white border-2 border-black rounded-lg text-sm font-bold focus:outline-none focus:ring-2 focus:ring-[#4F8CFF]";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40" onClick={onClose}>
      <div
        className="relative w-full max-w-sm p-6 bg-white border-2 border-black rounded-xl shadow-[4px_4px_0px_0px_rgba(0,0,0,1)] text-left"
        onClick={(e) => e.stopPropagation()}
      >
        <button onClick={onClose} aria-label="Close" className="absolute top-3 right-3 p-1 cursor-pointer">
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2.5 mb-5">
          <div className="p-1.5 bg-[#4F8CFF] border-2 border-black rounded-lg">
            <Shield className="w-5 h-5 text-white stroke-[2.5]" />
          </div>
          <h2 className="font-display font-black text-lg">{mode === "signin" ? "Sign in" : "Create account"}</h2>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          {mode === "signup" && (
            <input className={input} placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          )}
          <input
            className={input}
            type="email"
            required
            placeholder="Email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <input
            className={input}
            type="password"
            required
            minLength={8}
            placeholder="Password (8+ characters)"
            autoComplete={mode === "signin" ? "current-password" : "new-password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />

          {error && <p className="text-xs font-bold text-rose-700">{error}</p>}

          <button
            type="submit"
            disabled={busy}
            className="w-full py-2.5 bg-[#4F8CFF] text-white border-2 border-black rounded-lg font-display font-black text-sm shadow-[2.5px_2.5px_0px_0px_rgba(0,0,0,1)] disabled:opacity-60 cursor-pointer"
          >
            {busy ? "Please wait..." : mode === "signin" ? "Sign in" : "Create account"}
          </button>
        </form>

        {googleEnabled && (
          <>
            <div className="my-4 text-center text-[10px] font-mono font-bold text-slate-500">OR</div>
            <button
              onClick={handleGoogle}
              className="w-full py-2.5 bg-white border-2 border-black rounded-lg font-display font-black text-sm hover:bg-slate-50 cursor-pointer"
            >
              Continue with Google (connects Gmail)
            </button>
          </>
        )}

        <p className="mt-5 text-xs text-slate-700 text-center">
          {mode === "signin" ? "New here?" : "Already have an account?"}{" "}
          <button
            type="button"
            onClick={() => {
              setMode(mode === "signin" ? "signup" : "signin");
              setError(null);
            }}
            className="font-black text-[#4F8CFF] cursor-pointer"
          >
            {mode === "signin" ? "Create an account" : "Sign in"}
          </button>
        </p>
      </div>
    </div>
  );
}
