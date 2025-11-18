import { Outlet } from 'react-router-dom'
import shieldLogo from '@/assets/shield-logo.svg'

const AuthLayout = () => {
  return (
    <div className="min-h-screen relative overflow-hidden bg-gradient-to-br from-slate-100 via-white to-slate-200 dark:from-slate-900 dark:via-gray-900 dark:to-slate-800">
      {/* Soft decorative glow behind the card */}
      <div className="absolute -top-32 left-1/2 -translate-x-1/2 w-[42rem] h-[42rem] bg-gradient-to-br from-blue-500/20 via-indigo-500/20 to-cyan-500/20 rounded-full blur-3xl pointer-events-none" />

      <div className="relative z-10 flex flex-col justify-center items-center py-12 px-6 sm:px-6 lg:px-8">
        <div className="w-full max-w-md text-center">
          <div className="mx-auto flex items-center justify-center gap-3">
            <img src={shieldLogo} alt="SecurityAI" className="h-12 w-12 drop-shadow-lg" />
            <span className="text-3xl font-semibold tracking-tight text-gray-900 dark:text-white">SecurityAI</span>
          </div>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">Intelligent Cyber Defense</p>
        </div>

        <div className="mt-8 w-full max-w-md">
          <div className="glass-card py-8 px-6 sm:px-10 shadow-xl">
            <Outlet />
          </div>
        </div>
      </div>
    </div>
  )
}

export default AuthLayout