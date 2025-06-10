import axios, { AxiosInstance, AxiosError } from 'axios';
import { AuthResponse, LoginCredentials, RegisterData, User, ProfileUpdateData, ApiError, UserProfileResponse, AdminProfileResponse } from '../types';

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
  async userLogin(credentials: LoginCredentials): Promise<AuthResponse | undefined> {
    try {
      const response = await this.userApi.post<AuthResponse>('/user/auth/login', credentials);
      this.showNotification('Logged in successfully!', 'success');
      return response.data;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      return undefined;
    }
  }

  async userRegister(data: RegisterData): Promise<boolean> {
    try {
      await this.userApi.post('/user/auth/register', data);
      this.showNotification('Registration successful! Please log in.', 'success');
      return true; // Indicate success
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      return false; // Indicate failure
    }
  }

  // Admin Authentication
  async adminLogin(credentials: LoginCredentials): Promise<AuthResponse | undefined> {
    try {
      const response = await this.adminApi.post<AuthResponse>('/admin/auth/login', credentials);
      this.showNotification('Admin logged in successfully!', 'success');
      return response.data;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      return undefined;
    }
  }

  // User Profile
  async getUserProfile(): Promise<User | undefined> {
    try {
      const response = await this.userApi.get<UserProfileResponse>('/user/profile');
      return response.data.user;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      return undefined;
    }
  }

  async updateUserProfile(data: ProfileUpdateData): Promise<UserProfileResponse | undefined> {
    try {
      const response = await this.userApi.put<UserProfileResponse>('/user/profile', data);
      this.showNotification('Profile updated successfully!', 'success');
      return response.data;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      return undefined;
    }
  }

  async changeUserPassword(
    passwordData: { old_password: string; new_password: string }
  ): Promise<boolean> {
    try {
      await this.userApi.put("/user/auth/change-password", passwordData);
      this.showNotification("Password updated successfully!", "success");
      return true;
    } catch (error: any) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      return false;
    }
  }

  // Admin Management
  async getAllUsers(): Promise<User[] | undefined> {
    try {
      const response = await this.adminApi.get<User[]>('/admin/users');
      return response.data;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      return undefined;
    }
  }

  async getUserById(userId: number): Promise<User | undefined> {
    try {
      const response = await this.adminApi.get<User>(`/admin/users/${userId}`);
      return response.data;
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      return undefined;
    }
  }

  async deactivateUser(userId: number, username: string): Promise<void> {
    try {
      await this.adminApi.post(`/admin/users/${userId}/deactivate`);
      this.showNotification(`${username} deactivated successfully!`, 'success');
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
    }
  }

  async activateUser(userId: number, username: string): Promise<void> {
    try {
      await this.adminApi.post(`/admin/users/${userId}/activate`);
      this.showNotification(`${username} activated successfully!`, 'success');
    } catch (error) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
    }
  }

  async updateAdminProfile(
    adminData: { username?: string; email?: string; name?: string }
  ): Promise<AdminProfileResponse | undefined> {
    try {
      const response = await this.adminApi.put<AdminProfileResponse>(
        "/admin/profile",
        adminData
      );
      this.showNotification("Profile updated successfully!", "success");
      return response.data;
    } catch (error: any) {
      this.handleError(error);
      return undefined;
    }
  }

  async verifyAdminToken(): Promise<AdminProfileResponse | undefined> {
    try {
      const response = await this.adminApi.get<AdminProfileResponse>('/admin/auth/verify');
      return response.data;
    } catch (error: any) {
      this.handleError(error);
      return undefined;
    }
  }

  async changeAdminPassword(
    passwordData: { old_password: string; new_password: string }
  ): Promise<boolean> {
    try {
      await this.adminApi.put("/admin/auth/change-password", passwordData);
      this.showNotification("Password updated successfully!", "success");
      return true;
    } catch (error: any) {
      this.showNotification(this.handleError(error as AxiosError<ApiError>).message, 'error');
      return false;
    }
  }

  private handleError(error: AxiosError<ApiError>): Error {
    if (error.response) {
      if (error.response.status === 401) {
        return new Error(error.response.data?.error || 'Invalid credentials');
      } else if (error.response.status === 400) {
        return new Error(error.response.data?.error || error.response.data?.message || 'Registration failed: Please check your input.');
      } else if (error.response.data && error.response.data.message) {
        return new Error(error.response.data.message);
      } else {
        return new Error(`Request failed with status code ${error.response.status}`);
      }
    }
    return new Error('Network error occurred or no response received');
  }
}

export const apiService = new ApiService();