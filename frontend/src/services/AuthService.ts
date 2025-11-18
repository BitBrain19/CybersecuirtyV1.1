import { api } from './api'

export const AuthService = {
  login: async (email: string, password: string) => {
    // Backend expects OAuth2PasswordRequestForm (username + password) as form-encoded
    const params = new URLSearchParams()
    params.append('username', email)
    params.append('password', password)
    const response = await api.post('/auth/login', params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    return response.data
  },

  logout: async () => {
    // Backend does not expose logout; perform client-side logout
    return { success: true }
  },

  refreshToken: async () => {
    // Backend refresh requires an authenticated user; call `/auth/refresh-token`
    const response = await api.post('/auth/refresh-token')
    return response.data
  },

  getCurrentUser: async () => {
    // Not implemented on backend; placeholder
    return null
  },
}