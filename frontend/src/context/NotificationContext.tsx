import React, { createContext, useContext, useState, useCallback, ReactNode, useEffect, useRef } from 'react';

interface Notification {
  id: string;
  message: string;
  type: 'success' | 'error' | 'info';
}

interface NotificationContextType {
  showNotification: (message: string, type?: Notification['type']) => void;
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined);

interface NotificationProviderProps {
  children: ReactNode;
}

export const NotificationProvider: React.FC<NotificationProviderProps> = ({ children }) => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const timerRefs = useRef<Map<string, NodeJS.Timeout>>(new Map());

  const showNotification = useCallback((message: string, type: Notification['type'] = 'info') => {
    const id = Math.random().toString(36).substring(2, 9);
    setNotifications((prev) => {
      const newNotifications = [...prev, { id, message, type }];
      // Clear any existing timer for this ID if it somehow exists (shouldn't happen with new IDs)
      if (timerRefs.current.has(id)) {
        clearTimeout(timerRefs.current.get(id)!);
      }
      // Set a new timer to remove this specific notification
      const timer = setTimeout(() => {
        removeNotification(id);
      }, 5000);
      timerRefs.current.set(id, timer);
      return newNotifications;
    });
  }, []);

  const removeNotification = useCallback((id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
    // Clear the timer reference once the notification is removed
    if (timerRefs.current.has(id)) {
      clearTimeout(timerRefs.current.get(id)!);
      timerRefs.current.delete(id);
    }
  }, []);

  // Cleanup timers on unmount
  useEffect(() => {
    return () => {
      timerRefs.current.forEach(timer => clearTimeout(timer));
      timerRefs.current.clear();
    };
  }, []);

  return (
    <NotificationContext.Provider value={{ showNotification }}>
      {children}
      <div className="fixed top-4 right-4 z-50 space-y-2 max-w-xs min-w-64">
        {notifications.map((notification) => (
          <div
            key={notification.id}
            className={`p-3 text-sm rounded-md shadow-lg text-white transition-all duration-300 transform
              ${notification.type === 'success' ? 'bg-green-500' : ''}
              ${notification.type === 'error' ? 'bg-red-500' : ''}
              ${notification.type === 'info' ? 'bg-blue-500' : ''}
            `}
            role="alert"
          >
            <div className="flex justify-between items-center">
              <span>{notification.message}</span>
              <button onClick={() => removeNotification(notification.id)} className="ml-2 text-white font-bold opacity-75 hover:opacity-100 focus:outline-none">
                &times;
              </button>
            </div>
          </div>
        ))}
      </div>
    </NotificationContext.Provider>
  );
};

export const useNotification = () => {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
}; 