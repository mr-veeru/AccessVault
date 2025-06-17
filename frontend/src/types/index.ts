export interface User {
  id: number;
  email: string;
  username: string;
  name: string;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login: string | null;
}

export interface Admin {
  id: number;
  username: string;
  email: string;
  name?: string;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
}

export interface LoginCredentials {
  password: string;
  username_or_email?: string;
}

export interface RegisterData {
  username: string;
  name: string;
  email: string;
  password: string;
}

export interface ProfileUpdateData {
  username?: string;
  name?: string;
  email?: string;
  current_password?: string;
  new_password?: string;
}

export interface ApiError {
  error: string;
  message: string;
  statusCode: number;
}

export interface UserProfileResponse {
  message: string;
  user: User;
}

export interface AdminProfileResponse {
  message: string;
  admin: Admin;
} 