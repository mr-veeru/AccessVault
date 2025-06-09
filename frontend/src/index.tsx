import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App'; // Will be App.tsx after rename
import { BrowserRouter } from 'react-router-dom';
import { NotificationProvider } from './context/NotificationContext';

const root = ReactDOM.createRoot(document.getElementById('root') as HTMLElement);
root.render(
  <React.StrictMode>
    <BrowserRouter>
      <NotificationProvider>
        <App />
      </NotificationProvider>
    </BrowserRouter>
  </React.StrictMode>
); 