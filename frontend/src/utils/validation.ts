// frontend/src/utils/validation.ts

// Basic email format validation
export const isValidEmail = (email: string): boolean => {
  if (!email) return false;
  const pattern = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;
  return pattern.test(email.toLowerCase());
};

// Username format validation (lowercase letters, numbers, and underscores)
export const isValidUsername = (username: string): boolean => {
  if (!username) return false;
  const pattern = /^[a-z0-9_]+$/;
  return pattern.test(username.toLowerCase());
};

// Password strength validation (matches backend Config settings)
export const validatePassword = (password: string): string | true => {
  const PASSWORD_MIN_LENGTH = 8;
  const PASSWORD_REQUIRE_UPPER = true;
  const PASSWORD_REQUIRE_LOWER = true;
  const PASSWORD_REQUIRE_DIGIT = true;
  const PASSWORD_REQUIRE_SPECIAL = true;

  if (password.length < PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`;
  }

  if (PASSWORD_REQUIRE_UPPER && !/[A-Z]/.test(password)) {
    return 'Password must contain at least one uppercase letter.';
  }

  if (PASSWORD_REQUIRE_LOWER && !/[a-z]/.test(password)) {
    return 'Password must contain at least one lowercase letter.';
  }

  if (PASSWORD_REQUIRE_DIGIT && !/\d/.test(password)) {
    return 'Password must contain at least one digit.';
  }

  if (PASSWORD_REQUIRE_SPECIAL && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return 'Password must contain at least one special character.';
  }

  return true; // Password is valid
}; 