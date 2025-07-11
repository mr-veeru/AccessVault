import React, { useState, useEffect } from 'react';
import { User } from '../types';
import { apiService } from '../services/api';
import { useNotification } from '../context/NotificationContext';
import ConfirmationDialog from './ConfirmationDialog';
import { FiEye, FiEyeOff } from 'react-icons/fi';

interface UserProfileProps {
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

const UserProfile: React.FC<UserProfileProps> = ({ onLogout }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState<Partial<User>>({});
  const [passwordData, setPasswordData] = useState({
    old_password: '',
    new_password: '',
    confirm_new_password: '',
  });
  const { showNotification } = useNotification();
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [showDeactivateConfirm, setShowDeactivateConfirm] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  useEffect(() => {
    fetchUserProfile();
  }, []);

  const fetchUserProfile = async () => {
    try {
      const userData = await apiService.getUserProfile();
      if (userData) {
        setUser(userData);
        setFormData({
          username: userData.username,
          name: userData.name,
          email: userData.email,
        });
      } else {
        setUser(null);
      }
    } catch (err) {
      // Error handling is done by apiService
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
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
      const success = await apiService.changeUserPassword({
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const updatedUserResponse = await apiService.updateUserProfile(formData);
      if (updatedUserResponse && updatedUserResponse.user) {
        setUser(updatedUserResponse.user);
        setIsEditing(false);
      }
    } catch (err) {
      // Removed local error setting, apiService already handles notifications
    }
  };

  const handleDeactivateAccount = () => {
    setShowDeactivateConfirm(true);
  };

  const confirmDeactivateAccount = async () => {
      try {
        const success = await apiService.deactivateOwnAccount();
        if (success) {
          onLogout();
        }
      } catch (error) {
        showNotification('Failed to deactivate account. Please try again.', 'error');
    } finally {
      setShowDeactivateConfirm(false);
    }
  };

  const cancelDeactivateAccount = () => {
    setShowDeactivateConfirm(false);
  };

  const handleDeleteAccount = () => {
    setShowDeleteConfirm(true);
  };

  const confirmDeleteAccount = async () => {
    try {
      const success = await apiService.deleteUserAccount();
      if (success) {
        onLogout();
      }
    } catch (error) {
      showNotification('Failed to delete account. Please try again.', 'error');
    } finally {
      setShowDeleteConfirm(false);
    }
  };

  const cancelDeleteAccount = () => {
    setShowDeleteConfirm(false);
  };

  if (!user) {
    return <div className="flex justify-center items-center h-screen text-primary-600 dark:text-primary-300">Loading user profile...</div>;
  }

  return (
    <div className="max-w-2xl mx-auto p-6 bg-light-card dark:bg-dark-card rounded-lg shadow-custom-light dark:shadow-custom-dark border border-light-border dark:border-dark-border">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-serif font-bold text-primary-600 dark:text-primary-300">User Profile</h2>
      </div>

      {isEditing ? (
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-light-text dark:text-dark-text">Username</label>
            <input
              type="text"
              name="username"
              value={formData.username || ''}
              onChange={handleInputChange}
              className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 dark:bg-dark-background dark:text-dark-text bg-light-background"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-light-text dark:text-dark-text">Name</label>
            <input
              type="text"
              name="name"
              value={formData.name || ''}
              onChange={handleInputChange}
              className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 dark:bg-dark-background dark:text-dark-text bg-light-background"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-light-text dark:text-dark-text">Email</label>
            <input
              type="email"
              name="email"
              value={formData.email || ''}
              onChange={handleInputChange}
              className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 dark:bg-dark-background dark:text-dark-text bg-light-background"
            />
          </div>

          <div className="flex justify-end space-x-4">
            <button
              type="button"
              onClick={() => setIsEditing(false)}
              className="px-4 py-2 border border-light-border dark:border-dark-border rounded-md text-light-text dark:text-dark-text hover:bg-light-background dark:hover:bg-dark-background transition-colors shadow-sm"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors shadow-md"
            >
              Save Changes
            </button>
          </div>
        </form>
      ) : (
        <div className="space-y-4">
          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Username:</h3>
            <p className="text-light-text dark:text-dark-text">{user.username}</p>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Name:</h3>
            <p className="text-light-text dark:text-dark-text">{user.name || 'N/A'}</p>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Email:</h3>
            <p className="text-light-text dark:text-dark-text">{user.email}</p>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Account Status:</h3>
            <p className="mt-1 text-lg">
              <span className={`px-2 py-1 rounded-full text-sm ${
                user.is_active
                  ? 'bg-accent text-white'
                  : 'bg-destructive text-white'
              }`}>
                {user.is_active ? 'Active' : 'Inactive'}
              </span>
            </p>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Member Since:</h3>
            <p className="text-light-text dark:text-dark-text">
              {user.created_at ? formatDate(user.created_at) : 'N/A'}
            </p>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Last Login:</h3>
            <p className="text-light-text dark:text-dark-text">
              {user.last_login ? formatDate(user.last_login) : 'N/A'}
            </p>
          </div>

          <div className="flex justify-end space-x-4">
            <button
              onClick={() => setIsEditing(true)}
              className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors shadow-md"
            > 
              Edit Profile
            </button>
          </div>
        </div>
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

      <div className="mt-8 p-6 bg-light-card dark:bg-dark-card shadow-custom-light dark:shadow-custom-dark rounded-lg border border-light-border dark:border-dark-border">
        <h3 className="text-2xl font-serif font-bold mb-4 text-primary-600 dark:text-primary-300 text-center">Account Actions</h3>
        <div className="flex justify-center space-x-4">
          <button
            onClick={handleDeactivateAccount}
            className="px-4 py-2 bg-destructive text-white rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-destructive focus:ring-offset-2 shadow-md"
          >
            Deactivate My Account
          </button>
          <button
            onClick={handleDeleteAccount}
            className="px-4 py-2 bg-destructive text-white rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-destructive focus:ring-offset-2 shadow-md"
          >
            Delete My Account
          </button>
        </div>
      </div>

      <ConfirmationDialog
        message="Are you sure you want to deactivate your account? This action cannot be undone."
        isOpen={showDeactivateConfirm}
        onConfirm={confirmDeactivateAccount}
        onCancel={cancelDeactivateAccount}
      />

      <ConfirmationDialog
        message="Are you sure you want to delete your account? This action cannot be undone."
        isOpen={showDeleteConfirm}
        onConfirm={confirmDeleteAccount}
        onCancel={cancelDeleteAccount}
      />
    </div>
  );
};

export default UserProfile; 