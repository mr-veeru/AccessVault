import React, { useState, useEffect } from 'react';
import { User, RegisterData } from '../types';
import { apiService } from '../services/api';
import { Link } from 'react-router-dom';
import ConfirmationDialog from './ConfirmationDialog';
import { FiEye, FiEyeOff } from 'react-icons/fi';

interface AdminDashboardProps {
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

const AdminDashboard: React.FC<AdminDashboardProps> = ({ onLogout }) => {
  const [users, setUsers] = useState<User[]>([]);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [newUserData, setNewUserData] = useState<Partial<RegisterData>>({});
  const [confirmPassword, setConfirmPassword] = useState('');
  const [addUserError, setAddUserError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [showEditUserModal, setShowEditUserModal] = useState(false);
  const [editUserData, setEditUserData] = useState<Partial<User>>({});
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [userToDelete, setUserToDelete] = useState<{ id: number; username: string } | null>(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    setIsLoading(true);
    setError('');
    try {
      const usersData = await apiService.getAllUsers();
      if (usersData) {
        setUsers(usersData);
      }
    } catch (err: any) {
      if (err.response?.status === 401) {
        // Token expired or invalid, redirect to login
        onLogout();
        return;
      }
      setError('Failed to fetch users');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteUser = async (userId: number, username: string) => {
    setUserToDelete({ id: userId, username });
    setShowDeleteConfirm(true);
  };

  const confirmDeleteUser = async () => {
    if (!userToDelete) return;
    
    try {
      await apiService.deleteUser(userToDelete.id);
      fetchUsers();
      if (selectedUser?.id === userToDelete.id) {
          setSelectedUser(null);
        }
      } finally {
      setShowDeleteConfirm(false);
      setUserToDelete(null);
    }
  };

  const cancelDeleteUser = () => {
    setShowDeleteConfirm(false);
    setUserToDelete(null);
  };

  const handleViewUserDetails = async (userId: number) => {
    try {
      const userData = await apiService.getUserById(userId);
      if (userData) {
        setSelectedUser(userData);
      }
    } catch (err: any) {
      if (err.response?.status === 401) {
        // Token expired or invalid, redirect to login
        onLogout();
        return;
      }
      // apiService handles other notifications
    }
  };

  const handleAddUserSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setAddUserError(null);
    if (!newUserData.username || !newUserData.email || !newUserData.password || !newUserData.name || !confirmPassword) {
      setAddUserError('All fields are required.');
      return;
    }
    if (newUserData.password !== confirmPassword) {
      setAddUserError('Passwords do not match.');
      return;
    }
    try {
      await apiService.createUser({ ...(newUserData as RegisterData), confirmPassword });
      fetchUsers();
      setShowAddUserModal(false);
      setNewUserData({});
      setConfirmPassword('');
    } catch (err) {
      // Error handling is now done by apiService
    }
  };

  const handleAddUserChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = event.target;
    setNewUserData((prevData: Partial<RegisterData>) => ({
      ...prevData,
      [name]: value,
    }));
  };

  const togglePasswordVisibility = () => {
    setShowPassword((prev) => !prev);
  };

  const handleEditUserClick = (user: User) => {
    setEditUserData(user);
    setShowEditUserModal(true);
  };

  const handleEditUserChange = (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = event.target;

    if (name === 'is_active') {
      setEditUserData((prevData: Partial<User>) => ({
        ...prevData,
        [name]: value === 'true',
      }));
    } else {
      setEditUserData((prevData: Partial<User>) => ({
        ...prevData,
        [name]: value,
      }));
    }
  };

  const handleUpdateUserSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!editUserData.id) return;

    try {
      const updatedUser = await apiService.updateUser(editUserData.id, editUserData);
      fetchUsers();
      setShowEditUserModal(false);
      setSelectedUser(null);
    } catch (err: any) {
      // Handle specific error cases
      if (err.response?.status === 401) {
        // Token expired or invalid, redirect to login
        onLogout();
        return;
      }
      if (err.response?.status === 400 && err.response?.data?.error?.includes('Cannot edit your own account')) {
        // Show specific message for admin self-editing
        console.error('Admin cannot edit their own account via this interface');
        return;
      }
      // apiService handles other notifications
    }
  };

  if (isLoading) {
    return <div className="flex justify-center items-center h-screen text-primary-600 dark:text-primary-300">Loading users...</div>;
  }

  return (
    <div className="max-w-7xl mx-auto p-6 font-sans">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-3xl font-serif font-bold text-primary-600 dark:text-primary-300">Admin Dashboard</h2>
        <div className="flex space-x-4">
          <Link
            to="/admin-profile"
            className="px-4 py-2 bg-secondary-600 text-white rounded hover:bg-secondary-700 transition-colors shadow-md"
          >
            Edit Profile
          </Link>
          <button
            onClick={() => setShowAddUserModal(true)}
            className="px-4 py-2 bg-accent text-white rounded hover:bg-green-700 transition-colors shadow-md"
          >
            Add New User
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-4 bg-destructive/10 border border-destructive text-destructive rounded-md">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="bg-light-card dark:bg-dark-card rounded-lg shadow-custom-light dark:shadow-custom-dark p-6 border border-light-border dark:border-dark-border">
            <h3 className="text-xl font-serif font-semibold mb-4 text-primary-600 dark:text-primary-300">User Management</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-light-border dark:divide-dark-border">
                <thead className="bg-light-background dark:bg-dark-background">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-secondary-700 dark:text-secondary-300 uppercase tracking-wider">
                      Username
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-secondary-700 dark:text-secondary-300 uppercase tracking-wider">
                      Email
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-secondary-700 dark:text-secondary-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-secondary-700 dark:text-secondary-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-light-card dark:bg-dark-card divide-y divide-light-border dark:divide-dark-border">
                  {users.map((user) => (
                    <tr key={user.id} className="hover:bg-light-background dark:hover:bg-dark-background transition-colors duration-200">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-light-text dark:text-dark-text">
                        {user.username}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-light-text dark:text-dark-text">
                        {user.email}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 py-1 text-xs rounded-full font-semibold ${
                          user.is_active
                            ? 'bg-accent text-white'
                            : 'bg-destructive text-white'
                        }`}>
                          {user.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button
                          onClick={() => handleViewUserDetails(user.id)}
                          className="text-primary-600 hover:text-primary-800 dark:text-primary-400 dark:hover:text-primary-200 mr-3 transition-colors duration-200"
                        >
                          View
                        </button>
                        <button
                          onClick={() => handleEditUserClick(user)}
                          className="text-secondary-600 hover:text-secondary-800 dark:text-secondary-400 dark:hover:text-secondary-200 mr-3 transition-colors duration-200"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDeleteUser(user.id, user.username)}
                          className="text-destructive hover:text-red-800 dark:text-destructive-400 dark:hover:text-red-200 transition-colors duration-200"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {selectedUser && (
        <div className="lg:col-span-1">
            <div className="bg-light-card dark:bg-dark-card rounded-lg shadow-custom-light dark:shadow-custom-dark p-6 border border-light-border dark:border-dark-border">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-xl font-serif font-semibold text-primary-600 dark:text-primary-300">User Details</h3>
                <button
                  onClick={() => setSelectedUser(null)}
                  className="text-light-text dark:text-dark-text hover:text-secondary-600 dark:hover:text-secondary-400 transition-colors duration-200"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <h4 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Username:</h4>
                  <p className="text-light-text dark:text-dark-text">{selectedUser.username}</p>
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Email:</h4>
                  <p className="text-light-text dark:text-dark-text">{selectedUser.email}</p>
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Name:</h4>
                  <p className="text-light-text dark:text-dark-text">{selectedUser.name || 'N/A'}</p>
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Role:</h4>
                  <div className="flex items-center space-x-2">
                    <p className="text-light-text dark:text-dark-text">{selectedUser.role}</p>
                  </div>
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Account Status:</h4>
                  <p className="mt-1">
                    <span className={`px-2 py-1 text-xs rounded-full font-semibold ${
                      selectedUser.is_active
                        ? 'bg-accent text-white'
                        : 'bg-destructive text-white'
                    }`}>
                      {selectedUser.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </p>
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Member Since:</h4>
                  <p className="text-light-text dark:text-dark-text">
                    {selectedUser.created_at ? formatDate(selectedUser.created_at) : 'N/A'}
                  </p>
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-secondary-600 dark:text-secondary-300">Last Login:</h4>
                  <p className="text-light-text dark:text-dark-text">
                    {selectedUser.last_login ? formatDate(selectedUser.last_login) : 'N/A'}
                  </p>
                </div>
              </div>
            </div>
            </div>
          )}
      </div>

      {/* Add User Modal */}
      {showAddUserModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4">
          <div className="bg-light-card dark:bg-dark-card rounded-lg shadow-custom-light dark:shadow-custom-dark p-8 w-full max-w-md border border-light-border dark:border-dark-border">
            <h3 className="text-2xl font-serif font-bold mb-6 text-center text-primary-600 dark:text-primary-300">Add New User</h3>
            <form onSubmit={handleAddUserSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-light-text dark:text-dark-text">Username</label>
                <input
                  type="text"
                  name="username"
                  value={newUserData.username || ''}
                  onChange={handleAddUserChange}
                  className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-light-text dark:text-dark-text">Name</label>
                <input
                  type="text"
                  name="name"
                  value={newUserData.name || ''}
                  onChange={handleAddUserChange}
                  className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-light-text dark:text-dark-text">Email</label>
                <input
                  type="email"
                  name="email"
                  value={newUserData.email || ''}
                  onChange={handleAddUserChange}
                  className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-light-text dark:text-dark-text">Password</label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    name="password"
                    value={newUserData.password || ''}
                    onChange={handleAddUserChange}
                    className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text pr-10"
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
              </div>
              <div>
                <label className="block text-sm font-medium text-light-text dark:text-dark-text">Confirm Password</label>
                <input
                  type="password"
                  name="confirmPassword"
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text"
                  required
                />
              </div>
              {addUserError && <p className="text-destructive text-sm mt-2">{addUserError}</p>}
              <div className="flex justify-end space-x-4">
                <button
                  type="button"
                  onClick={() => setShowAddUserModal(false)}
                  className="px-4 py-2 border border-light-border dark:border-dark-border rounded-md text-light-text dark:text-dark-text hover:bg-light-background dark:hover:bg-dark-background transition-colors shadow-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors shadow-md"
                >
                  Add User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit User Modal */}
      {showEditUserModal && editUserData.id && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4">
          <div className="bg-light-card dark:bg-dark-card rounded-lg shadow-custom-light dark:shadow-custom-dark p-8 w-full max-w-md border border-light-border dark:border-dark-border">
            <h3 className="text-2xl font-serif font-bold mb-6 text-center text-primary-600 dark:text-primary-300">Edit User</h3>
            <form onSubmit={handleUpdateUserSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-light-text dark:text-dark-text">Username</label>
                <input
                  type="text"
                  name="username"
                  value={editUserData.username || ''}
                  onChange={handleEditUserChange}
                  className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-light-text dark:text-dark-text">Name</label>
                <input
                  type="text"
                  name="name"
                  value={editUserData.name || ''}
                  onChange={handleEditUserChange}
                  className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-light-text dark:text-dark-text">Email</label>
                <input
                  type="email"
                  name="email"
                  value={editUserData.email || ''}
                  onChange={handleEditUserChange}
                  className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-light-text dark:text-dark-text">Role</label>
                <select
                  name="role"
                  value={editUserData.role || 'user'}
                    onChange={handleEditUserChange}
                  className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text py-2 px-3"
                  >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div>
                <label htmlFor="is_active" className="block text-sm font-medium text-light-text dark:text-dark-text">Account Status</label>
                <select
                  id="is_active"
                  name="is_active"
                  value={String(editUserData.is_active)}
                  onChange={handleEditUserChange}
                  className="mt-1 block w-full rounded-md border-light-border dark:border-dark-border shadow-sm focus:border-primary-500 focus:ring-primary-500 bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text py-2 px-3"
                >
                  <option value="true">Activate</option>
                  <option value="false">Deactivate</option>
                </select>
              </div>
              <div className="flex justify-end space-x-4">
                <button
                  type="button"
                  onClick={() => setShowEditUserModal(false)}
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
          </div>
        </div>
      )}

      <ConfirmationDialog
        message={`Are you sure you want to delete user "${userToDelete?.username}"? This action cannot be undone.`}
        isOpen={showDeleteConfirm}
        onConfirm={confirmDeleteUser}
        onCancel={cancelDeleteUser}
      />
    </div>
  );
};

export default AdminDashboard; 