import React, { useState, useEffect, useCallback } from 'react';
import { User } from '../types';
import { apiService } from '../services/api';
import { useNotification } from '../context/NotificationContext';
import { useNavigate } from 'react-router-dom';
import ConfirmationDialog from './ConfirmationDialog';
import { FiEye, FiEyeOff } from 'react-icons/fi';

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
  const [admin, setAdmin] = useState<User | null>(null);
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
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
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

  const confirmDeleteAccount = async () => {
    setShowDeleteConfirm(false);
    try {
      const success = await apiService.deleteAdminAccount();
      if (success) {
        onLogout();
      }
    } catch (error) {
      showNotification('Failed to delete account. Please try again.', 'error');
    }
  };

  const cancelDeleteAccount = () => {
    setShowDeleteConfirm(false);
  };

  if (isLoading) {
    return <div className="flex justify-center items-center h-screen text-primary-600 dark:text-primary-300">Loading admin profile...</div>;
  }

  if (!admin) {
    return <div className="text-center mt-8 text-destructive">Admin profile not found.</div>;
  }

  return (
    <div className="max-w-4xl mx-auto p-6 bg-light-card dark:bg-dark-card shadow-custom-light dark:shadow-custom-dark rounded-lg border border-light-border dark:border-dark-border mt-8 font-sans">
      <h2 className="text-3xl font-serif font-bold mb-6 text-primary-600 dark:text-primary-300 text-center">Admin Profile</h2>

      {!isEditing ? (
        <div className="space-y-4">
          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Username:</h3>
            <p className="text-light-text dark:text-dark-text">{admin.username}</p>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Name:</h3>
            <p className="text-light-text dark:text-dark-text">{admin.name || 'N/A'}</p>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Email:</h3>
            <p className="text-light-text dark:text-dark-text">{admin.email}</p>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Role:</h3>
            <p className="text-light-text dark:text-dark-text">{admin.role}</p>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Member Since:</h3>
            <p className="text-light-text dark:text-dark-text">
              {admin.created_at ? formatDate(admin.created_at) : 'N/A'}
            </p>
          </div>
          <div className="flex justify-center mt-6">
            <button
              onClick={() => setIsEditing(true)}
              className="px-6 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-opacity-50 transition-colors shadow-md"
            >
              Edit Profile
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleUpdateProfile} className="space-y-4">
          <div>
            <label htmlFor="username" className="block text-sm font-medium text-light-text dark:text-dark-text">Username</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleInputChange}
              className="mt-1 block w-full px-3 py-2 border border-light-border dark:border-dark-border rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text"
            />
          </div>
          <div>
            <label htmlFor="name" className="block text-sm font-medium text-light-text dark:text-dark-text">Name</label>
            <input
              type="text"
              id="name"
              name="name"
              value={formData.name}
              onChange={handleInputChange}
              className="mt-1 block w-full px-3 py-2 border border-light-border dark:border-dark-border rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text"
            />
          </div>
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-light-text dark:text-dark-text">Email</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              className="mt-1 block w-full px-3 py-2 border border-light-border dark:border-dark-border rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text"
            />
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              type="button"
              onClick={() => setIsEditing(false)}
              className="px-4 py-2 border border-light-border dark:border-dark-border rounded-md text-light-text dark:text-dark-text hover:bg-light-background dark:hover:bg-dark-background transition-colors shadow-sm"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 transition-colors shadow-md"
            >
              Save Changes
            </button>
          </div>
        </form>
      )}

      <div className="mt-8 p-6 bg-light-card dark:bg-dark-card shadow-custom-light dark:shadow-custom-dark rounded-lg border border-light-border dark:border-dark-border">
        <h3 className="text-2xl font-serif font-bold mb-4 text-primary-600 dark:text-primary-300 text-center">Change Password</h3>
        <form onSubmit={handleChangePassword} className="space-y-4">
          <div>
            <label htmlFor="old_password" className="block text-sm font-medium text-light-text dark:text-dark-text">Old Password</label>
            <div className="relative">
              <input
                type={showOldPassword ? 'text' : 'password'}
                id="old_password"
                name="old_password"
                value={passwordData.old_password}
                onChange={handlePasswordChange}
                className="mt-1 block w-full px-3 py-2 border border-light-border dark:border-dark-border rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text pr-10"
              />
              <button
                type="button"
                onClick={() => setShowOldPassword(!showOldPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5 text-secondary-400 hover:text-secondary-600 transition-colors duration-200"
              >
                {showOldPassword ? <FiEyeOff size={20} /> : <FiEye size={20} />}
              </button>
            </div>
          </div>
          <div>
            <label htmlFor="new_password" className="block text-sm font-medium text-light-text dark:text-dark-text">New Password</label>
            <div className="relative">
              <input
                type={showNewPassword ? 'text' : 'password'}
                id="new_password"
                name="new_password"
                value={passwordData.new_password}
                onChange={handlePasswordChange}
                className="mt-1 block w-full px-3 py-2 border border-light-border dark:border-dark-border rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text pr-10"
              />
              <button
                type="button"
                onClick={() => setShowNewPassword(!showNewPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5 text-secondary-400 hover:text-secondary-600 transition-colors duration-200"
              >
                {showNewPassword ? <FiEyeOff size={20} /> : <FiEye size={20} />}
              </button>
            </div>
          </div>
          <div>
            <label htmlFor="confirm_new_password" className="block text-sm font-medium text-light-text dark:text-dark-text">Confirm New Password</label>
            <div className="relative">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                id="confirm_new_password"
                name="confirm_new_password"
                value={passwordData.confirm_new_password}
                onChange={handlePasswordChange}
                className="mt-1 block w-full px-3 py-2 border border-light-border dark:border-dark-border rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text pr-10"
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5 text-secondary-400 hover:text-secondary-600 transition-colors duration-200"
              >
                {showConfirmPassword ? <FiEyeOff size={20} /> : <FiEye size={20} />}
              </button>
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 transition-colors shadow-md"
            >
              Change Password
            </button>
          </div>
        </form>
      </div>

      <div className="mt-8 flex justify-center space-x-4">
        <button
          onClick={() => navigate('/admin-dashboard')}
          className="px-6 py-2 bg-secondary-600 text-white rounded-md hover:bg-secondary-700 focus:outline-none focus:ring-2 focus:ring-secondary-500 focus:ring-offset-2 shadow-md"
        >
          Back to Dashboard
        </button>
        <button
          onClick={() => setShowDeleteConfirm(true)}
          className="px-6 py-2 bg-destructive text-white rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-destructive focus:ring-offset-2 shadow-md"
        >
          Delete Account
        </button>
      </div>

      <ConfirmationDialog
        message="Are you sure you want to delete your account? This action cannot be undone."
        isOpen={showDeleteConfirm}
        onConfirm={confirmDeleteAccount}
        onCancel={cancelDeleteAccount}
      />
    </div>
  );
};

export default AdminProfile; 