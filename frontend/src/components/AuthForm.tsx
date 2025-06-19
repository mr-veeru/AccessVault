import React, { useState } from 'react';
import { LoginCredentials, RegisterData } from '../types';
import { useNotification } from '../context/NotificationContext';
import { isValidEmail, isValidUsername, validatePassword } from '../utils/validation';
import { FiEye, FiEyeOff } from 'react-icons/fi';

interface AuthFormProps {
  type: 'login' | 'register';
  onSubmit: (data: LoginCredentials | RegisterData) => Promise<void>;
  isAdmin?: boolean;
}

const AuthForm: React.FC<AuthFormProps> = ({ type, onSubmit, isAdmin = false }) => {
  const [formData, setFormData] = useState<Partial<RegisterData>>({});
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [errors, setErrors] = useState<{[key: string]: string}>({});
  const { showNotification } = useNotification();

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    const processedValue = (name === 'username' || name === 'email') ? value.toLowerCase() : value;
    setFormData(prev => ({ ...prev, [name]: processedValue }));

    // Clear error for the current field as user types
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const validateField = (name: string, value: string): string => {
    let error = '';
    if (type === 'register') {
      if (name === 'email') {
        if (!value) error = 'Email is required.';
        else if (!isValidEmail(value)) error = 'Invalid email format.';
      } else if (name === 'username') {
        if (!value) error = 'Username is required.';
        else if (!isValidUsername(value)) error = 'Username can only contain lowercase letters, numbers, and underscores.';
      } else if (name === 'password') {
        if (!value) error = 'Password is required.';
        else {
          const passwordValidationResult = validatePassword(value);
          if (passwordValidationResult !== true) error = passwordValidationResult;
        }
      } else if (name === 'confirmPassword') {
        if (!value) error = 'Please confirm your password.';
        else if (value !== formData.password) error = 'Passwords do not match.';
      } else if (name === 'name' && !value) {
        error = 'Name is required.';
      }
    } else { // type === 'login'
      if (name === 'email') {
        if (!value) error = 'Email/Username is required.';
      } else if (name === 'password' && !value) {
        error = 'Password is required.';
      }
    }
    return error;
  };

  const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    const error = validateField(name, value);
    setErrors(prev => ({ ...prev, [name]: error }));
  };

  const validateForm = (): boolean => {
    let newErrors: {[key: string]: string} = {};
    let isValid = true;

    if (type === 'register') {
      const fields: Array<keyof RegisterData> = ['username', 'email', 'password', 'name', 'confirmPassword'];
      for (const field of fields) {
        const error = validateField(field, formData[field] || '');
        if (error) {
          newErrors[field] = error;
          isValid = false;
        }
      }
      // Extra check for password match
      if (formData.password !== formData.confirmPassword) {
        newErrors.confirmPassword = 'Passwords do not match.';
        isValid = false;
      }
    } else { // type === 'login'
      // Explicitly validate login fields, which are handled as 'email' and 'password' in formData
      const emailError = validateField('email', formData.email || '');
      if (emailError) {
        newErrors.email = emailError;
        isValid = false;
      }
      const passwordError = validateField('password', formData.password || '');
      if (passwordError) {
        newErrors.password = passwordError;
        isValid = false;
      }
    }
    setErrors(newErrors);
    return isValid;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateForm()) {
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      if (type === 'register') {
        await onSubmit(formData as RegisterData);
      } else {
        // Ensure email and password are not undefined after validation
        await onSubmit({ username_or_email: formData.email!, password: formData.password! });
      }
    } catch (err) {
      console.error('Error in AuthForm handleSubmit:', err);
      showNotification(err instanceof Error ? err.message : 'Authentication failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  const togglePasswordVisibility = () => {
    setShowPassword(prev => !prev);
  };

  return (
    <div className="max-w-md mx-auto mt-12 p-8 bg-light-card dark:bg-dark-card rounded-lg shadow-custom-light dark:shadow-custom-dark border border-light-border dark:border-dark-border">
      <h2 className="text-2xl font-serif font-bold mb-6 text-center text-primary-600 dark:text-primary-300">
        {type === 'login' 
          ? isAdmin 
            ? 'Admin Login' 
            : 'Welcome Back!'
          : 'Join AccessVault'}
      </h2>
      {type === 'login' && isAdmin && (
        <div className="mb-6 p-4 bg-secondary-100 dark:bg-secondary-900 rounded-lg">
          <p className="text-secondary-700 dark:text-secondary-300 text-sm">
            This is the admin login portal. Please use your admin credentials to access the admin dashboard.
          </p>
        </div>
      )}
      <form onSubmit={handleSubmit} className="space-y-4">
        {type === 'register' && (
          <>
            <div>
              <label className="block text-sm font-medium text-light-text dark:text-dark-text">Username</label>
              <input
                type="text"
                name="username"
                value={formData.username || ''}
                onChange={handleChange}
                onBlur={handleBlur}
                className={`mt-1 block w-full rounded-md shadow-sm dark:bg-dark-background dark:text-dark-text ${errors.username ? 'border-destructive focus:border-destructive focus:ring-destructive' : 'border-light-border dark:border-dark-border focus:border-primary-500 focus:ring-primary-500'} bg-light-background`}
                required
              />
              {errors.username && <p className="mt-1 text-sm text-destructive">{errors.username}</p>}
            </div>
            <div>
              <label className="block text-sm font-medium text-light-text dark:text-dark-text">Name</label>
              <input
                type="text"
                name="name"
                value={formData.name || ''}
                onChange={handleChange}
                onBlur={handleBlur}
                className={`mt-1 block w-full rounded-md shadow-sm dark:bg-dark-background dark:text-dark-text ${errors.name ? 'border-destructive focus:border-destructive focus:ring-destructive' : 'border-light-border dark:border-dark-border focus:border-primary-500 focus:ring-primary-500'} bg-light-background`}
                required
              />
              {errors.name && <p className="mt-1 text-sm text-destructive">{errors.name}</p>}
            </div>
          </>
        )}
        <div>
          <label className="block text-sm font-medium text-light-text dark:text-dark-text">
            {type === 'login' ? 'Email or Username' : 'Email'}
          </label>
          <input
            type={type === 'login' ? 'text' : 'email'}
            name="email"
            value={formData.email || ''}
            onChange={handleChange}
            onBlur={handleBlur}
            className={`mt-1 block w-full rounded-md shadow-sm dark:bg-dark-background dark:text-dark-text ${errors.email ? 'border-destructive focus:border-destructive focus:ring-destructive' : 'border-light-border dark:border-dark-border focus:border-primary-500 focus:ring-primary-500'} bg-light-background`}
            required
          />
          {errors.email && <p className="mt-1 text-sm text-destructive">{errors.email}</p>}
        </div>
        <div>
          <label className="block text-sm font-medium text-light-text dark:text-dark-text">Password</label>
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              name="password"
              value={formData.password || ''}
              onChange={handleChange}
              onBlur={handleBlur}
              className={`mt-1 block w-full rounded-md shadow-sm dark:bg-dark-background dark:text-dark-text ${errors.password ? 'border-destructive focus:border-destructive focus:ring-destructive' : 'border-light-border dark:border-dark-border focus:border-primary-500 focus:ring-primary-500'} pr-10 bg-light-background`}
              required
            />
            <button
              type="button"
              onClick={togglePasswordVisibility}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5 text-secondary-400 hover:text-secondary-600 transition-colors duration-200"
            >
              {showPassword ? <FiEyeOff size={20} /> : <FiEye size={20} />}
            </button>
          </div>
          {errors.password && <p className="mt-1 text-sm text-destructive">{errors.password}</p>}
        </div>
        {type === 'register' && (
          <div>
            <label className="block text-sm font-medium text-light-text dark:text-dark-text">Confirm Password</label>
            <div className="relative">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                name="confirmPassword"
                value={formData.confirmPassword || ''}
                onChange={handleChange}
                onBlur={handleBlur}
                className={`mt-1 block w-full rounded-md shadow-sm dark:bg-dark-background dark:text-dark-text ${errors.confirmPassword ? 'border-destructive focus:border-destructive focus:ring-destructive' : 'border-light-border dark:border-dark-border focus:border-primary-500 focus:ring-primary-500'} pr-10 bg-light-background`}
                required
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(prev => !prev)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5 text-secondary-400 hover:text-secondary-600 transition-colors duration-200"
              >
                {showConfirmPassword ? <FiEyeOff size={20} /> : <FiEye size={20} />}
              </button>
            </div>
            {errors.confirmPassword && <p className="mt-1 text-sm text-destructive">{errors.confirmPassword}</p>}
          </div>
        )}
        <button
          type="submit"
          className="w-full py-2 px-4 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors shadow-md"
          disabled={loading}
        >
          {loading ? 'Please wait...' : type === 'login' ? 'Login' : 'Register'}
        </button>
      </form>
    </div>
  );
};

export default AuthForm;
