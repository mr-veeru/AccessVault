// Test script to verify frontend handles 429 responses correctly

// Mock the notification function
const mockShowNotification = (message, type) => {
  console.log(`[${type.toUpperCase()}] ${message}`);
};

// Simulate a 429 response
const simulate429Response = () => {
  const error = {
    response: {
      status: 429,
      data: {
        message: 'Rate limit exceeded. Please try again in 60 seconds.',
        error: 'Too Many Requests'
      }
    }
  };
  
  // This is how the frontend handleError method would process it
  const handleError = (error) => {
    if (error.response) {
      if (error.response.status === 401) {
        return new Error(error.response.data?.error || 'Invalid credentials');
      } else if (error.response.status === 400) {
        return new Error(error.response.data?.error || error.response.data?.message || 'Registration failed: Please check your input.');
      } else if (error.response.status === 429) {
        // Rate limit exceeded
        const rateLimitMessage = error.response.data?.message || 'Too many requests. Please wait a moment before trying again.';
        return new Error(rateLimitMessage);
      } else if (error.response.data && error.response.data.message) {
        return new Error(error.response.data.message);
      } else {
        return new Error(`Request failed with status code ${error.response.status}`);
      }
    }
    return new Error('Network error occurred or no response received');
  };

  const processedError = handleError(error);
  mockShowNotification(processedError.message, 'error');
};

console.log('Testing frontend 429 response handling...');
simulate429Response();
console.log('Test completed!'); 