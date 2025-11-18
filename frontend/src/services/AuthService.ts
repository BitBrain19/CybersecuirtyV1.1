import { api } from './api'

export const AuthService = {
  login: async (email: string, password: string) => {
    // Mock login - backend doesn't have auth endpoints yet
    // Store token in localStorage for session
    const mockToken = 'mock_token_' + Date.now()
    localStorage.setItem('accessToken', mockToken)
    localStorage.setItem('refreshToken', mockToken)
    return { 
      access_token: mockToken, 
      refresh_token: mockToken,
      user: { email, id: '1' }
    }
  },

  logout: async () => {
    // Clear localStorage
    localStorage.removeItem('accessToken')
    localStorage.removeItem('refreshToken')
    return { success: true }
  },

  refreshToken: async () => {
    // Mock refresh
    const mockToken = 'mock_token_' + Date.now()
    localStorage.setItem('accessToken', mockToken)
    return { access_token: mockToken }
  },

  getCurrentUser: async () => {
    // Return mock user
    return { id: '1', email: 'admin@cybergard.ai', role: 'admin' }
  },
}