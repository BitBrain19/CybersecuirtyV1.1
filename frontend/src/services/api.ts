import axios from 'axios'
import { API_URL } from '@/utils/constants'

// Shared axios instance with base URL
export const api = axios.create({
  baseURL: API_URL,
})

// Include bearer token from localStorage on every request
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken')
    if (token) {
      config.headers = config.headers || {}
      ;(config.headers as any).Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Basic 401 handling: clear tokens and send user to login
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = (error as any).config
    if (error.response?.status === 401 && !originalRequest?._retry) {
      originalRequest._retry = true
      localStorage.removeItem('accessToken')
      localStorage.removeItem('refreshToken')
      window.location.href = '/login'
      return Promise.reject(error)
    }
    return Promise.reject(error)
  }
)