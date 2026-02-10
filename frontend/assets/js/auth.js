// frontend/assets/js/auth.js

class AuthService {
    constructor() {
        this.apiBase = 'http://localhost:3000/api';
        this.csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    }

    async request(endpoint, options = {}) {
        const url = `${this.apiBase}${endpoint}`;
        
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                ...(this.csrfToken && { 'X-CSRF-Token': this.csrfToken })
            },
            credentials: 'include'
        };

        const config = { ...defaultOptions, ...options };

        try {
            const response = await fetch(url, config);
            
            // Handle HTTP errors
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    // Register
    async register(userData) {
        try {
            const response = await this.request('/auth/register', {
                method: 'POST',
                body: JSON.stringify(userData)
            });

            // Store user info in localStorage
            localStorage.setItem('user', JSON.stringify(response.user));
            this.setAuthState(true);

            return response;
        } catch (error) {
            throw new Error(`Registration failed: ${error.message}`);
        }
    }

    // Login
    async login(credentials) {
        try {
            const response = await this.request('/auth/login', {
                method: 'POST',
                body: JSON.stringify(credentials)
            });

            localStorage.setItem('user', JSON.stringify(response.user));
            this.setAuthState(true);

            return response;
        } catch (error) {
            throw new Error(`Login failed: ${error.message}`);
        }
    }

    // Logout
    async logout() {
        try {
            await this.request('/auth/logout', {
                method: 'POST'
            });

            localStorage.removeItem('user');
            this.setAuthState(false);
            
            // Redirect to login page
            window.location.href = '/login.html';
        } catch (error) {
            console.error('Logout failed:', error);
        }
    }

    // Get current user
    getCurrentUser() {
        const user = localStorage.getItem('user');
        return user ? JSON.parse(user) : null;
    }

    // Check if user is authenticated
    isAuthenticated() {
        return !!this.getCurrentUser();
    }

    // Check if user is admin
    isAdmin() {
        const user = this.getCurrentUser();
        return user && user.role === 'admin';
    }

    // Set authentication state in DOM
    setAuthState(isAuthenticated) {
        document.body.classList.toggle('authenticated', isAuthenticated);
        document.body.classList.toggle('unauthenticated', !isAuthenticated);
    }

    // Refresh token
    async refreshToken() {
        try {
            await this.request('/auth/refresh', {
                method: 'POST'
            });
            return true;
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.logout();
            return false;
        }
    }

    // Password reset
    async requestPasswordReset(email) {
        return await this.request('/auth/forgot-password', {
            method: 'POST',
            body: JSON.stringify({ email })
        });
    }

    async resetPassword(token, password) {
        return await this.request(`/auth/reset-password/${token}`, {
            method: 'POST',
            body: JSON.stringify({ password })
        });
    }

    // Update profile
    async updateProfile(profileData) {
        return await this.request('/users/profile', {
            method: 'PUT',
            body: JSON.stringify(profileData)
        });
    }

    // Change password
    async changePassword(currentPassword, newPassword) {
        return await this.request('/users/change-password', {
            method: 'POST',
            body: JSON.stringify({ currentPassword, newPassword })
        });
    }

    // Delete account
    async deleteAccount(password) {
        return await this.request('/users/account', {
            method: 'DELETE',
            body: JSON.stringify({ password })
        });
    }
}

// Form validation utilities
class FormValidator {
    static validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    static validatePassword(password) {
        const minLength = 12;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[^A-Za-z0-9]/.test(password);

        if (password.length < minLength) return 'Password must be at least 12 characters';
        if (!hasUpperCase) return 'Password must contain at least one uppercase letter';
        if (!hasLowerCase) return 'Password must contain at least one lowercase letter';
        if (!hasNumbers) return 'Password must contain at least one number';
        if (!hasSpecialChar) return 'Password must contain at least one special character';
        
        return null;
    }

    static validateUsername(username) {
        if (username.length < 3 || username.length > 50) {
            return 'Username must be 3-50 characters';
        }
        
        const usernameRegex = /^[a-zA-Z0-9_.-]+$/;
        if (!usernameRegex.test(username)) {
            return 'Username can only contain letters, numbers, dots, dashes and underscores';
        }
        
        return null;
    }

    static showError(inputElement, message) {
        const formGroup = inputElement.closest('.form-group');
        const existingError = formGroup.querySelector('.form-error');
        
        if (existingError) {
            existingError.textContent = message;
            return;
        }

        const errorElement = document.createElement('div');
        errorElement.className = 'form-error';
        errorElement.textContent = message;
        
        formGroup.appendChild(errorElement);
        inputElement.classList.add('error');
    }

    static clearError(inputElement) {
        const formGroup = inputElement.closest('.form-group');
        const errorElement = formGroup.querySelector('.form-error');
        
        if (errorElement) {
            errorElement.remove();
        }
        
        inputElement.classList.remove('error');
    }

    static showSuccess(inputElement, message) {
        const formGroup = inputElement.closest('.form-group');
        const existingSuccess = formGroup.querySelector('.form-success');
        
        if (existingSuccess) {
            existingSuccess.textContent = message;
            return;
        }

        const successElement = document.createElement('div');
        successElement.className = 'form-success';
        successElement.textContent = message;
        
        formGroup.appendChild(successElement);
        inputElement.classList.add('success');
    }
}

// Initialize auth service
const authService = new AuthService();

// Auto-refresh token every 14 minutes
setInterval(() => {
    if (authService.isAuthenticated()) {
        authService.refreshToken();
    }
}, 14 * 60 * 1000);