import axios, { AxiosInstance, AxiosError } from 'axios';
import { AuthResponse, LoginCredentials, RegisterData, User, ProfileUpdateData, ApiError, UserProfileResponse } from '../types';

// We will import useNotification where apiService is initialized (e.g., in App.tsx)
// and pass the showNotification function to apiService.initialize(showNotificationFunc)

class ApiService {
  private userApi: AxiosInstance;
  private adminApi: AxiosInstance;
  private showNotification: (message: string, type?: 'success' | 'error' | 'info') => void;

  constructor() {
    this.userApi = axios.create({
      baseURL: 'http://localhost:5002',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.adminApi = axios.create({
      baseURL: 'http://localhost:5001',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Initialize with a no-op function, will be set by initialize function
    this.showNotification = () => {};

    // Add request interceptor for authentication
    this.userApi.interceptors.request.use((config) => {
      const token = localStorage.getItem('userToken');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    this.adminApi.interceptors.request.use((config) => {
      const token = localStorage.getItem('adminToken');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
  }

  // Public method to initialize the showNotification function
  public initialize(showNotificationFunc: (message: string, type?: 'success' | 'error' | 'info') => void) {
    this.showNotification = showNotificationFunc;
  }

  // User Authentication
  async userLogin(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      const response = await this.userApi.post<AuthResponse>('/user/auth/login', credentials);
      this.showNotification('Logged in successfully!', 'success');
      return response.data;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      throw error;
    }
  }

  async userRegister(data: RegisterData): Promise<void> {
    try {
      await this.userApi.post('/user/auth/register', data);
      this.showNotification('Registration successful! Please log in.', 'success');
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      throw error;
    }
  }

  // Admin Authentication
  async adminLogin(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      const response = await this.adminApi.post<AuthResponse>('/admin/auth/login', credentials);
      this.showNotification('Admin logged in successfully!', 'success');
      return response.data;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      throw error;
    }
  }

  // User Profile
  async getUserProfile(): Promise<User> {
    try {
      const response = await this.userApi.get<UserProfileResponse>('/user/profile');
      return response.data.user;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      throw error;
    }
  }

  async updateUserProfile(data: ProfileUpdateData): Promise<User> {
    try {
      const response = await this.userApi.put<User>('/user/profile', data);
      this.showNotification('Profile updated successfully!', 'success');
      return response.data;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      throw error;
    }
  }

  // Admin Management
  async getAllUsers(): Promise<User[]> {
    try {
      const response = await this.adminApi.get<User[]>('/admin/users');
      return response.data;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      throw error;
    }
  }

  async getUserById(userId: number): Promise<User> {
    try {
      const response = await this.adminApi.get<User>(`/admin/users/${userId}`);
      return response.data;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      throw error;
    }
  }

  async deactivateUser(userId: number): Promise<void> {
    try {
      await this.adminApi.post(`/admin/users/${userId}/deactivate`);
      this.showNotification(`User ${userId} deactivated successfully!`, 'success');
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      throw error;
    }
  }

  async activateUser(userId: number): Promise<void> {
    try {
      await this.adminApi.post(`/admin/users/${userId}/activate`);
      this.showNotification(`User ${userId} activated successfully!`, 'success');
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      throw error;
    }
  }

  private handleError(error: AxiosError<ApiError>): Error {
    if (error.response?.data) {
      return new Error(error.response.data.message || 'An error occurred');
    }
    return new Error('Network error occurred');
  }
}

export const apiService = new ApiService();