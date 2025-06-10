import React, { useState, useEffect, useCallback } from 'react';
import { Admin } from '../types';
import { apiService } from '../services/api';
import { useNotification } from '../context/NotificationContext';
import { useNavigate } from 'react-router-dom';

interface AdminProfileProps {
  onLogout: () => void;
}

const formatDate = (dateString: string) => {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  }).replace(/ /g, '-');
};

const AdminProfile: React.FC<AdminProfileProps> = ({ onLogout }) => {
  const [admin, setAdmin] = useState<Admin | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    name: '',
  });
  const [passwordData, setPasswordData] = useState({
    old_password: '',
    new_password: '',
    confirm_new_password: '',
  });
  const [isLoading, setIsLoading] = useState(true);
  const { showNotification } = useNotification();
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const navigate = useNavigate();

  const fetchAdminProfile = useCallback(async () => {
    try {
      setIsLoading(true);
      const response = await apiService.verifyAdminToken();
      if (response && response.admin) {
        setAdmin(response.admin);
        setFormData({
          username: response.admin.username || '',
          email: response.admin.email || '',
          name: response.admin.name || '',
        });
      }
    } catch (error) {
      showNotification('Failed to fetch admin profile.', 'error');
    } finally {
      setIsLoading(false);
    }
  }, [showNotification]);

  useEffect(() => {
    fetchAdminProfile();
  }, [fetchAdminProfile]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setPasswordData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passwordData.old_password || !passwordData.new_password || !passwordData.confirm_new_password) {
      showNotification('All password fields are required.', 'error');
      return;
    }
    if (passwordData.new_password !== passwordData.confirm_new_password) {
      showNotification('New password and confirm password do not match.', 'error');
      return;
    }
    if (passwordData.old_password === passwordData.new_password) {
      showNotification('New password cannot be the same as old password.', 'error');
      return;
    }

    try {
      const success = await apiService.changeAdminPassword({
        old_password: passwordData.old_password,
        new_password: passwordData.new_password,
      });
      if (success) {
        setPasswordData({ old_password: '', new_password: '', confirm_new_password: '' });
      }
    } catch (error) {
      showNotification('Failed to change password. Please try again.', 'error');
    }
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const updatedAdminResponse = await apiService.updateAdminProfile(formData);
      if (updatedAdminResponse && updatedAdminResponse.admin) {
        setAdmin(updatedAdminResponse.admin);
        setIsEditing(false);
      }
    } catch (error) {
      showNotification('Failed to update admin profile.', 'error');
    }
  };

  if (isLoading) {
    return <div className="flex justify-center items-center h-screen">Loading admin profile...</div>;
  }

  if (!admin) {
    return <div className="text-center mt-8 text-red-500">Admin profile not found.</div>;
  }

  return (
    <div className="max-w-4xl mx-auto p-6 bg-white dark:bg-gray-800 shadow-md rounded-lg mt-8">
      <h2 className="text-3xl font-bold mb-6 text-gray-900 dark:text-white text-center">Admin Profile</h2>

      {!isEditing ? (
        <div className="space-y-4">
          <div>
            <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300">Username:</h3>
            <p className="text-gray-900 dark:text-white">{admin.username}</p>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300">Name:</h3>
            <p className="text-gray-900 dark:text-white">{admin.name || 'N/A'}</p>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300">Email:</h3>
            <p className="text-gray-900 dark:text-white">{admin.email}</p>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300">Role:</h3>
            <p className="text-gray-900 dark:text-white">{admin.role}</p>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300">Member Since:</h3>
            <p className="text-gray-900 dark:text-white">
              {admin.created_at ? formatDate(admin.created_at) : 'N/A'}
            </p>
          </div>
          <div className="flex justify-center mt-6">
            <button
              onClick={() => setIsEditing(true)}
              className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-colors"
            >
              Edit Profile
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleUpdateProfile} className="space-y-4">
          <div>
            <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Username</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleInputChange}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
          <div>
            <label htmlFor="name" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Name</label>
            <input
              type="text"
              id="name"
              name="name"
              value={formData.name}
              onChange={handleInputChange}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Email</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              type="button"
              onClick={() => setIsEditing(false)}
              className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
            >
              Save Changes
            </button>
          </div>
        </form>
      )}

      <div className="mt-8 p-6 bg-white dark:bg-gray-800 shadow-md rounded-lg">
        <h3 className="text-2xl font-bold mb-4 text-gray-900 dark:text-white text-center">Change Password</h3>
        <form onSubmit={handleChangePassword} className="space-y-4">
          <div>
            <label htmlFor="old_password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Old Password</label>
            <div className="relative">
              <input
                type={showOldPassword ? 'text' : 'password'}
                id="old_password"
                name="old_password"
                value={passwordData.old_password}
                onChange={handlePasswordChange}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white pr-10"
              />
              <button
                type="button"
                onClick={() => setShowOldPassword(!showOldPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5"
              >
                <svg className="h-5 w-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  {showOldPassword ? (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.05 3.05m-3.05-3.05L3 3z" />
                  ) : (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  )}
                  {showOldPassword ? null : (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  )}
                </svg>
              </button>
            </div>
          </div>
          <div>
            <label htmlFor="new_password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">New Password</label>
            <div className="relative">
              <input
                type={showNewPassword ? 'text' : 'password'}
                id="new_password"
                name="new_password"
                value={passwordData.new_password}
                onChange={handlePasswordChange}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white pr-10"
              />
              <button
                type="button"
                onClick={() => setShowNewPassword(!showNewPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5"
              >
                <svg className="h-5 w-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  {showNewPassword ? (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.05 3.05m-3.05-3.05L3 3z" />
                  ) : (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  )}
                  {showNewPassword ? null : (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  )}
                </svg>
              </button>
            </div>
          </div>
          <div>
            <label htmlFor="confirm_new_password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Confirm New Password</label>
            <div className="relative">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                id="confirm_new_password"
                name="confirm_new_password"
                value={passwordData.confirm_new_password}
                onChange={handlePasswordChange}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white pr-10"
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5"
              >
                <svg className="h-5 w-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  {showConfirmPassword ? (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.05 3.05m-3.05-3.05L3 3z" />
                  ) : (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  )}
                  {showConfirmPassword ? null : (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  )}
                </svg>
              </button>
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
            >
              Change Password
            </button>
          </div>
        </form>
      </div>

      <div className="flex justify-center mt-6">
        <button
          onClick={() => navigate('/admin-dashboard')}
          className="px-6 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-opacity-50 transition-colors"
        >
          Back to Dashboard
        </button>
      </div>
    </div>
  );
};

export default AdminProfile; 