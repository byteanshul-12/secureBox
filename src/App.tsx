import { useState, useEffect } from "react";
import { AnimatePresence, motion } from "motion/react";
import { authClient } from "./lib/auth-client.ts";
import { UserProfile } from "./types.ts";

// Import modular layouts
import LandingPage from "./components/LandingPage.tsx";
import Dashboard from "./components/Dashboard.tsx";
import EmailScanner from "./components/EmailScanner.tsx";
import AuthModal from "./components/AuthModal.tsx";

export default function App() {
  const { data: session, isPending, refetch } = authClient.useSession();
  const currentUser = ((session as any)?.user ?? null) as {
    id: string; email: string; name: string; image?: string | null; createdAt: string | Date;
    protectionLevel?: string; subscription?: string;
  } | null;

  // Navigation states
  const [currentPage, setCurrentPage] = useState<string>("landing"); // "landing" | "dashboard" | "sandbox"
  const [showAuthModal, setShowAuthModal] = useState(false);

  // Route to the dashboard on sign-in and back to the landing page on sign-out
  useEffect(() => {
    if (isPending) return;
    if (currentUser) {
      setShowAuthModal(false);
      setCurrentPage((page) => (page === "landing" ? "dashboard" : page));
    } else {
      setCurrentPage("landing");
    }
  }, [isPending, currentUser?.id]);

  const userProfile: UserProfile | null = currentUser
    ? {
        uid: currentUser.id,
        email: currentUser.email,
        displayName: currentUser.name,
        photoURL: currentUser.image || `https://api.dicebear.com/7.x/bottts/svg?seed=${currentUser.id}`,
        createdAt: new Date(currentUser.createdAt).toISOString(),
        lastLoginAt: new Date().toISOString(),
        protectionLevel: (currentUser.protectionLevel || "balanced") as UserProfile["protectionLevel"],
        subscription: (currentUser.subscription || "free") as UserProfile["subscription"],
      }
    : null;

  const handleLogout = async () => {
    await authClient.signOut();
  };

  if (isPending) {
    return (
      <div className="min-h-screen bg-[#F8F7F4] flex flex-col items-center justify-center space-y-4 font-mono text-slate-800">
        <div className="w-10 h-10 rounded-lg border-[3px] border-black bg-white shadow-[3px_3px_0px_0px_rgba(0,0,0,1)] flex items-center justify-center animate-spin">
          <div className="w-3 h-3 bg-[#4F8CFF] rounded-sm" />
        </div>
        <p className="text-xs font-bold tracking-widest uppercase">BOOTING SECUREBOX CORE...</p>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen bg-[#F8F7F4] text-slate-900 selection:bg-[#4F8CFF] selection:text-white font-sans">
      <AnimatePresence mode="wait">
        {currentPage === "landing" && (
          <motion.div
            key="landing-page"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
          >
            <LandingPage 
              onGoogleLogin={() => setShowAuthModal(true)} 
              onOtpLoginClick={() => setShowAuthModal(true)} 
            />
          </motion.div>
        )}

        {currentPage === "dashboard" && currentUser && (
          <motion.div
            key="dashboard-view"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
          >
            <Dashboard 
              user={currentUser}
              userProfile={userProfile}
              onLogout={handleLogout}
              onRefreshProfile={() => refetch()}
              onPageChange={setCurrentPage}
            />
          </motion.div>
        )}

        {currentPage === "sandbox" && (
          <motion.div
            key="sandbox-view"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
          >
            <EmailScanner onBackToDashboard={() => setCurrentPage("dashboard")} />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Shared Authentication Trigger modal overlay */}
      {showAuthModal && (
        <AuthModal 
          onClose={() => setShowAuthModal(false)}
        />
      )}
    </div>
  );
}
