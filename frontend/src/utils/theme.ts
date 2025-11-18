export type ThemePreference = 'light' | 'dark' | 'system'

const STORAGE_KEY = 'theme'

function getSystemPrefersDark(): boolean {
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
}

export function getStoredTheme(): ThemePreference | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === 'light' || v === 'dark' || v === 'system') return v
    return null
  } catch {
    return null
  }
}

export function applyTheme(theme: ThemePreference) {
  const isDark = theme === 'dark' || (theme === 'system' && getSystemPrefersDark())
  document.documentElement.classList.toggle('dark', isDark)
  try {
    localStorage.setItem(STORAGE_KEY, theme)
  } catch {
    // ignore storage errors
  }
}

export function applyInitialTheme() {
  const stored = getStoredTheme()
  const initial: ThemePreference = stored ?? 'system'
  applyTheme(initial)

  // Keep in sync with system preference when in 'system'
  if (initial === 'system' && window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const listener = () => applyTheme('system')
    mq.addEventListener?.('change', listener)
  }
}