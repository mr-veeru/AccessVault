import React, { useState, useEffect } from 'react';
import { Routes, Route, Link, useNavigate } from 'react-router-dom';
import { LoginCredentials, RegisterData } from './types';
import { apiService } from './services/api';
import AuthForm from './components/AuthForm';
import UserProfile from './components/UserProfile';
import AdminDashboard from './components/AdminDashboard';
import AdminProfile from './components/AdminProfile';
import { useNotification } from './context/NotificationContext';

const App: React.FC = () => {
  const [userToken, setUserToken] = useState<string | null>(localStorage.getItem('userToken'));
  const [adminToken, setAdminToken] = useState<string | null>(localStorage.getItem('adminToken'));
  const [darkMode, setDarkMode] = useState<boolean>(localStorage.getItem('darkMode') === 'true');
  const navigate = useNavigate();
  const { showNotification } = useNotification();

  useEffect(() => {
    apiService.initialize(showNotification);
  }, [showNotification]);

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  const handleLogin = async (credentials: LoginCredentials, type: 'admin' | 'user'): Promise<void> => {
    try {
      const response = type === 'admin'
        ? await apiService.adminLogin(credentials)
        : await apiService.userLogin(credentials);

      if (response && response.access_token) {
        if (type === 'admin') {
          setAdminToken(response.access_token);
          localStorage.setItem('adminToken', response.access_token);
        } else {
          setUserToken(response.access_token);
          localStorage.setItem('userToken', response.access_token);
        }
        navigate(`/${type}-dashboard`);
      }
    } catch (error) {
      // Error handling is done by apiService
    }
  };

  const handleRegister = async (data: LoginCredentials | RegisterData): Promise<void> => {
    try {
      const registrationSuccess = await apiService.userRegister(data as RegisterData);
      if (registrationSuccess) {
        navigate('/user-login');
      }
    } catch (error) {
      // Error handling is done by apiService
    }
  };

  const handleLogout = (): void => {
    setUserToken(null);
    setAdminToken(null);
    localStorage.removeItem('userToken');
    localStorage.removeItem('adminToken');
    navigate('/');
  };

  const toggleDarkMode = (): void => {
    setDarkMode(prevMode => {
      const newMode = !prevMode;
      localStorage.setItem('darkMode', String(newMode));
      return newMode;
    });
  };

  return (
    <div className="min-h-screen bg-light-background dark:bg-dark-background text-light-text dark:text-dark-text transition-colors duration-300 font-sans">
      <nav className="bg-primary-700 dark:bg-primary-950 p-4 shadow-custom-light dark:shadow-custom-dark">
        <ul className="flex justify-center space-x-6">
          {!userToken && !adminToken ? (
            <>
              <li>
                <Link to="/admin-login" className="text-white hover:text-primary-200 text-lg font-medium transition-colors duration-200">
                  Admin Login
                </Link>
              </li>
              <li>
                <Link to="/user-login" className="text-white hover:text-primary-200 text-lg font-medium transition-colors duration-200">
                  User Login
                </Link>
              </li>
              <li>
                <Link to="/user-register" className="text-white hover:text-primary-200 text-lg font-medium transition-colors duration-200">
                  User Register
                </Link>
              </li>
            </>
          ) : (
            <li>
              <button
                onClick={handleLogout}
                className="bg-destructive text-white font-bold py-2 px-4 rounded hover:bg-red-700 transition duration-200 shadow-md"
              >
                Logout
              </button>
            </li>
          )}
          <li>
            <button
              onClick={toggleDarkMode}
              className="bg-secondary-600 hover:bg-secondary-700 text-white font-bold py-2 px-4 rounded transition duration-200 shadow-md"
            >
              {darkMode ? 'Light Mode' : 'Dark Mode'}
            </button>
          </li>
        </ul>
      </nav>

      <Routes>
        <Route
          path="/admin-login"
          element={<AuthForm type="login" onSubmit={(creds) => handleLogin(creds, 'admin')} isAdmin={true} />}
        />
        <Route
          path="/user-login"
          element={<AuthForm type="login" onSubmit={(creds) => handleLogin(creds, 'user')} isAdmin={false} />}
        />
        <Route
          path="/user-register"
          element={<AuthForm type="register" onSubmit={handleRegister} isAdmin={false} />}
        />
        
        {userToken && (
          <Route
            path="/user-dashboard"
            element={<UserProfile onLogout={handleLogout} />}
          />
        )}
        {adminToken && (
          <Route
            path="/admin-dashboard"
            element={<AdminDashboard onLogout={handleLogout} />}
          />
        )}
        {adminToken && (
          <Route
            path="/admin-profile"
            element={<AdminProfile onLogout={handleLogout} />}
          />
        )}

        <Route
          path="*"
          element={
            !userToken && !adminToken ? (
              <h1 className="text-center text-3xl mt-12 text-primary-600 dark:text-primary-300 font-serif">
                Welcome! Please Login or Register
              </h1>
            ) : (
              <h1 className="text-center text-3xl mt-12 text-primary-600 dark:text-primary-300 font-serif">
                Dashboard (Select from Navbar)
              </h1>
            )
          }
        />
      </Routes>
    </div>
  );
};

export default App;