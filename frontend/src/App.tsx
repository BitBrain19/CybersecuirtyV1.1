import { Routes, Route } from "react-router-dom";
import { Suspense, lazy } from "react";
// Using Sonner Toaster instead of react-toastify
import { Toaster } from "@/components/ui/sonner";

// Layouts
import MainLayout from "./components/layouts/MainLayout";
import AuthLayout from "./components/layouts/AuthLayout";

// Pages
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Alerts = lazy(() => import("./pages/Alerts"));
const AttackPaths = lazy(() => import("./pages/AttackPaths"));
const Reports = lazy(() => import("./pages/Reports"));
const Settings = lazy(() => import("./pages/Settings"));
const SOAR = lazy(() => import("./pages/SOAR"));
const UEBA = lazy(() => import("./pages/UEBA"));
const EDR = lazy(() => import("./pages/EDR"));
const Login = lazy(() => import("./pages/auth/Login"));
const NotFound = lazy(() => import("./pages/NotFound"));

// Auth guard component
import AuthGuard from "./components/auth/AuthGuard";

function App() {
  return (
    <>
      <Suspense
        fallback={
          <div className="flex items-center justify-center h-screen">
            Loading...
          </div>
        }
      >
        <Routes>
          {/* Auth routes */}
          <Route element={<AuthLayout />}>
            <Route path="/login" element={<Login />} />
          </Route>

          {/* Protected routes */}
          <Route element={<AuthGuard />}>
            <Route element={<MainLayout />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/attack-paths" element={<AttackPaths />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/soar" element={<SOAR />} />
              <Route path="/ueba" element={<UEBA />} />
              <Route path="/edr" element={<EDR />} />
            </Route>
          </Route>

          {/* 404 route */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Suspense>
      <Toaster />
    </>
  );
}

export default App;
