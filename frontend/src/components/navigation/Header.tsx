import { useEffect, useState } from 'react'
import { Bars3Icon, BellIcon, MoonIcon, SunIcon, UserCircleIcon } from '@heroicons/react/24/outline'
import { useNavigate } from 'react-router-dom'
import { applyTheme, getStoredTheme } from '@/utils/theme'
import ShieldLogo from '@/assets/shield-logo.svg'

type HeaderProps = {
  sidebarOpen: boolean
  setSidebarOpen: (open: boolean) => void
}

const Header = ({ setSidebarOpen }: HeaderProps) => {
  const [darkMode, setDarkMode] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    const stored = getStoredTheme()
    const isDark = stored ? (stored === 'dark' || (stored === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)) : document.documentElement.classList.contains('dark')
    setDarkMode(isDark)
  }, [])

  const toggleDarkMode = () => {
    const newMode = !darkMode
    setDarkMode(newMode)
    applyTheme(newMode ? 'dark' : 'light')
  }

  const handleLogout = () => {
    // Clear auth tokens
    localStorage.removeItem('accessToken')
    localStorage.removeItem('refreshToken')
    
    // Redirect to login
    navigate('/login')
  }

  return (
  <header className="sticky top-0 z-10 flex-shrink-0 flex h-16 bg-white/70 dark:bg-gray-800/50 backdrop-blur border-b border-gray-200 dark:border-gray-700">
      <button
        type="button"
        className="px-4 border-r border-gray-200 dark:border-gray-700 text-gray-500 md:hidden"
        onClick={() => setSidebarOpen(true)}
      >
        <span className="sr-only">Open sidebar</span>
        <Bars3Icon className="h-6 w-6" aria-hidden="true" />
      </button>
      <div className="flex-1 px-4 flex justify-between">
        <div className="flex-1 flex items-center space-x-3">
          <img src={ShieldLogo} alt="SecurityAI" className="h-7 w-7 rounded-md shadow-sm" />
          <div className="flex flex-col leading-tight">
            <span className="text-lg font-semibold tracking-tight text-gray-900 dark:text-white">SecurityAI</span>
            <span className="text-xs text-gray-500 dark:text-gray-400">Adaptive Cyber Defense</span>
          </div>
        </div>
        <div className="ml-4 flex items-center md:ml-6 space-x-4">
          {/* Dark mode toggle */}
          <button
            type="button"
            className="bg-gray-100/70 dark:bg-gray-700/70 p-1 rounded-full text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            onClick={toggleDarkMode}
          >
            <span className="sr-only">{darkMode ? 'Switch to light mode' : 'Switch to dark mode'}</span>
            {darkMode ? (
              <SunIcon className="h-6 w-6" aria-hidden="true" />
            ) : (
              <MoonIcon className="h-6 w-6" aria-hidden="true" />
            )}
          </button>

          {/* Notifications */}
          <button
            type="button"
            className="bg-gray-100/70 dark:bg-gray-700/70 p-1 rounded-full text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            <span className="sr-only">View notifications</span>
            <BellIcon className="h-6 w-6" aria-hidden="true" />
          </button>

          {/* Profile dropdown */}
          <div className="ml-3 relative">
            <div>
              <button
                type="button"
                className="max-w-xs bg-gray-100/70 dark:bg-gray-700/70 rounded-full flex items-center text-sm focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                id="user-menu-button"
                aria-expanded="false"
                aria-haspopup="true"
                onClick={() => setUserMenuOpen(!userMenuOpen)}
              >
                <span className="sr-only">Open user menu</span>
                <UserCircleIcon className="h-8 w-8 rounded-full text-gray-600 dark:text-gray-300" />
              </button>
            </div>

            {userMenuOpen && (
              <div
                className="origin-top-right absolute right-0 mt-2 w-48 rounded-md shadow-lg py-1 bg-white/90 dark:bg-gray-800/90 backdrop-blur ring-1 ring-black/10 focus:outline-none"
                role="menu"
                aria-orientation="vertical"
                aria-labelledby="user-menu-button"
                tabIndex={-1}
              >
                <a
                  href="#"
                  className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                  role="menuitem"
                  tabIndex={-1}
                  id="user-menu-item-0"
                >
                  Your Profile
                </a>
                <a
                  href="#"
                  className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                  role="menuitem"
                  tabIndex={-1}
                  id="user-menu-item-1"
                >
                  Settings
                </a>
                <button
                  onClick={handleLogout}
                  className="w-full text-left block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                  role="menuitem"
                  tabIndex={-1}
                  id="user-menu-item-2"
                >
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}

export default Header