import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import jwtDecode from 'jwt-decode'
import { AuthService } from '../services/AuthService'

type User = {
  id: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  name: string
}

type AuthState = {
  user: User | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
  checkAuth: () => Promise<boolean>
}

export const useAuth = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,

      login: async (email: string, password: string) => {
        try {
          const response = await AuthService.login(email, password)
          const { access_token, refresh_token } = response

          // For mock tokens, create user directly without JWT decoding
          const user: User = {
            id: '1',
            email: email,
            role: 'admin',
            name: email.split('@')[0],
          }

          // Persist tokens for axios interceptor
          localStorage.setItem('accessToken', access_token)
          if (refresh_token) {
            localStorage.setItem('refreshToken', refresh_token)
          }

          set({
            user,
            accessToken: access_token,
            refreshToken: refresh_token ?? null,
            isAuthenticated: true,
          })
        } catch (error) {
          console.error('Login failed:', error)
          throw error
        }
      },

      logout: () => {
        // Client-side logout
        AuthService.logout()
          .catch((error) => console.error('Logout API error:', error))
          .finally(() => {
            localStorage.removeItem('accessToken')
            localStorage.removeItem('refreshToken')
            set({
              user: null,
              accessToken: null,
              refreshToken: null,
              isAuthenticated: false,
            })
          })
      },

      checkAuth: async () => {
        const { accessToken } = get()

        if (!accessToken) {
          set({ isAuthenticated: false })
          return false
        }

        try {
          // For mock tokens (starting with 'mock_token_'), skip JWT decoding
          if (accessToken.startsWith('mock_token_')) {
            set({ isAuthenticated: true })
            return true
          }

          // For real JWT tokens, decode and check expiration
          const decodedToken: any = jwtDecode(accessToken)
          const currentTime = Date.now() / 1000

          if (decodedToken.exp && decodedToken.exp > currentTime) {
            set({ isAuthenticated: true })
            return true
          }

          // Token expired; require re-login
          localStorage.removeItem('accessToken')
          localStorage.removeItem('refreshToken')
          set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false })
          return false
        } catch (error) {
          console.error('Token parse failed:', error)
          set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false })
          return false
        }
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        user: state.user,
      }),
    }
  )
)