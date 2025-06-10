import React, { useState, useEffect } from 'react';
import { User, RegisterData } from '../types';
import { apiService } from '../services/api';
import { Link } from 'react-router-dom';

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
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      setIsLoading(true);
      const userData = await apiService.getAllUsers();
      setUsers(userData || []);
      setError(null);
    } catch (err) {
      setError('Failed to fetch users');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeactivateUser = async (userId: number, username: string) => {
    try {
      await apiService.deactivateUser(userId, username);
      // Refresh the users list
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to deactivate user');
    }
  };

  const handleActivateUser = async (userId: number, username: string) => {
    try {
      await apiService.activateUser(userId, username);
      // Refresh the users list
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to activate user');
    }
  };

  const handleDeleteUser = async (userId: number, username: string) => {
    if (window.confirm(`Are you sure you want to delete user "${username}"? This action cannot be undone.`)) {
      try {
        await apiService.deleteUser(userId);
        // Refresh the users list
        fetchUsers();
        // Clear selected user if it was the deleted user
        if (selectedUser?.id === userId) {
          setSelectedUser(null);
        }
      } catch (err) {
        // Error handling is now done by apiService
      }
    }
  };

  const handleViewUserDetails = async (userId: number) => {
    try {
      const userData = await apiService.getUserById(userId);
      setSelectedUser(userData || null);
    } catch (err) {
      setError('Failed to fetch user details');
    }
  };

  const handleAddUserSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      if (!newUserData.username || !newUserData.email || !newUserData.password || !newUserData.name) {
        // The apiService.createUser will handle the notification for missing fields
        return;
      }
      await apiService.createUser(newUserData as RegisterData);
      // Refresh the users list
      fetchUsers();
      // Close the modal and reset form
      setShowAddUserModal(false);
      setNewUserData({}); // Reset form data
    } catch (err) {
      // Error handling is now done by apiService, so no explicit setError here
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

  if (isLoading) {
    return <div className="flex justify-center items-center h-screen">Loading...</div>;
  }

  return (
    <div className="max-w-7xl mx-auto p-6">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Admin Dashboard</h2>
        <div className="flex space-x-4">
          <Link
            to="/admin-profile"
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
          >
            Edit Profile
          </Link>
          <button
            onClick={onLogout}
            className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
          >
            Logout
          </button>
          <button
            onClick={() => setShowAddUserModal(true)}
            className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition-colors"
          >
            Add New User
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Users List */}
        <div className="lg:col-span-2">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
            <h3 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Users</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-700">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Username
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Email
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  {users.map((user) => (
                    <tr key={user.id}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                        {user.username}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                        {user.email}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 py-1 text-xs rounded-full ${
                          user.is_active
                            ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
                            : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
                        }`}>
                          {user.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button
                          onClick={() => handleViewUserDetails(user.id)}
                          className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300 mr-4"
                        >
                          View
                        </button>
                        {user.is_active ? (
                          <button
                            onClick={() => handleDeactivateUser(user.id, user.username)}
                            className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 mr-4"
                          >
                            Deactivate
                          </button>
                        ) : (
                          <button
                            onClick={() => handleActivateUser(user.id, user.username)}
                            className="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300 mr-4"
                          >
                            Activate
                          </button>
                        )}
                        <button
                          onClick={() => handleDeleteUser(user.id, user.username)}
                          className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
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

        {/* User Details */}
        <div className="lg:col-span-1">
          {selectedUser ? (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
              <h3 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">User Details</h3>
              <div className="space-y-4">
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Username</h4>
                  <p className="mt-1 text-lg text-gray-900 dark:text-white">{selectedUser.username}</p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Name</h4>
                  <p className="mt-1 text-lg text-gray-900 dark:text-white">{selectedUser.name}</p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Email</h4>
                  <p className="mt-1 text-lg text-gray-900 dark:text-white">{selectedUser.email}</p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Status</h4>
                  <p className="mt-1">
                    <span className={`px-2 py-1 rounded-full text-sm ${
                      selectedUser.is_active
                        ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
                        : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
                    }`}>
                      {selectedUser.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Member Since</h4>
                  <p className="mt-1 text-lg text-gray-900 dark:text-white">
                    {selectedUser.created_at ? formatDate(selectedUser.created_at) : 'N/A'}
                  </p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Last Login</h4>
                  <p className="mt-1 text-lg text-gray-900 dark:text-white">
                    {selectedUser.last_login ? formatDate(selectedUser.last_login) : 'N/A'}
                  </p>
                </div>
              </div>
              <div className="mt-6 flex justify-end">
                <button
                  onClick={() => setSelectedUser(null)}
                  className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-opacity-50 transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          ) : (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
              <p className="text-gray-500 dark:text-gray-400 text-center">
                Select a user to view their details
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Add New User Modal */}
      {showAddUserModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex justify-center items-center z-50">
          <div className="relative p-8 bg-white dark:bg-gray-800 w-full max-w-md mx-auto rounded-lg shadow-lg">
            <h3 className="text-xl font-semibold mb-6 text-gray-900 dark:text-white">Add New User</h3>
            <form onSubmit={handleAddUserSubmit} className="space-y-4">
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Username</label>
                <input
                  type="text"
                  id="username"
                  name="username"
                  value={newUserData.username || ''}
                  onChange={handleAddUserChange}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white"
                  required
                />
              </div>
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Email</label>
                <input
                  type="email"
                  id="email"
                  name="email"
                  value={newUserData.email || ''}
                  onChange={handleAddUserChange}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white"
                  required
                />
              </div>
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Password</label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    id="password"
                    name="password"
                    value={newUserData.password || ''}
                    onChange={handleAddUserChange}
                    className="block w-full pr-10 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white"
                    required
                  />
                  <button
                    type="button"
                    onClick={togglePasswordVisibility}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5 text-gray-500 dark:text-gray-400 focus:outline-none"
                  >
                    {showPassword ? (
                      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M3.988 5.844A8.25 8.25 0 0112 2.25c2.307 0 4.467.558 6.362 1.574M16.72 6.22a8.25 8.25 0 013.375 7.037m-1.588-4.947a1.125 1.125 0 111.588 1.588l-.348.348A2.25 2.25 0 0112 11.25c-1.234 0-2.25-.506-2.25-1.125v-.348M9.6 9.6a1.125 1.125 0 10-1.588 1.588l.348-.348m.348-.348C9.373 8.71 10.395 8.25 11.25 8.25c.619 0 1.125.251 1.125.563v.348m-.348-.348l-.348-.348A8.25 8.25 0 002.25 12c0 2.946.946 5.617 2.56 7.822m14.24-2.144A8.25 8.25 0 0021.75 12c0-2.946-.946-5.617-2.56-7.822m-1.588 4.947a1.125 1.125 0 11-1.588-1.588l.348-.348A2.25 2.25 0 0112 11.25c1.234 0 2.25.506 2.25 1.125v.348m.348.348l.348.348A8.25 8.25 0 0021.75 12c0 2.946-.946 5.617-2.56 7.822" />
                      </svg>
                    ) : (
                      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                        <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                    )}
                  </button>
                </div>
              </div>
              <div>
                <label htmlFor="name" className="block text-sm font-medium text-gray-700 dark:text-gray-300">Name</label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  value={newUserData.name || ''}
                  onChange={handleAddUserChange}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white"
                  required
                />
              </div>
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  type="button"
                  onClick={() => setShowAddUserModal(false)}
                  className="px-4 py-2 bg-gray-300 text-gray-800 rounded-md hover:bg-gray-400 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-opacity-50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-colors"
                >
                  Create User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard; 