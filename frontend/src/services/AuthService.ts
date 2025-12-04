import { api } from './api'

export const AuthService = {
  login: async (email: string, password: string) => {
    const formData = new URLSearchParams()
    formData.append('username', email)
    formData.append('password', password)

    const response = await api.post('/auth/login', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    })

    const { access_token, refresh_token } = response.data
    localStorage.setItem('accessToken', access_token)
    localStorage.setItem('refreshToken', refresh_token)

    const user = await AuthService.getCurrentUser()
    return {
      access_token,
      refresh_token,
      user
    }
  },

  logout: async () => {
    localStorage.removeItem('accessToken')
    localStorage.removeItem('refreshToken')
    return { success: true }
  },

  refreshToken: async () => {
    const response = await api.post('/auth/refresh-token')
    const { access_token } = response.data
    localStorage.setItem('accessToken', access_token)
    return { access_token }
  },

  getCurrentUser: async () => {
    const response = await api.get('/users/me')
    return response.data
  },
}