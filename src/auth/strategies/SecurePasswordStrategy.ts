import jwt from 'jsonwebtoken';
import CryptoJS from 'crypto-js';
import { Page, BrowserContext } from '@playwright/test';
import {
  BaseAuthenticationStrategy,
  AuthenticationCredentials,
  AuthenticationResult,
  UserData,
} from '@auth/strategies/base/AuthenticationStrategy';
import { AuthConfigManager } from '@auth/config/AuthConfig';
import { logger } from '@auth/utils/SecureLogger';

export interface SecureCredentials extends AuthenticationCredentials {
  email: string;
  password: string;
  role?: string;
  mfaToken?: string;
  captchaToken?: string;
}

export interface AuthResponse {
  success: boolean;
  token?: string;
  refreshToken?: string;
  userData?: {
    email: string;
    role: string;
    permissions: string[];
    lastLogin?: Date;
  };
  errorMessage?: string;
  expiresAt?: Date;
  requiresMFA?: boolean;
  captchaRequired?: boolean;
}

/**
 * Secure password authentication strategy with JWT tokens, rate limiting, and security features
 */
export class SecurePasswordStrategy extends BaseAuthenticationStrategy {
  public readonly name = 'secure-password';
  public readonly type = 'password' as const;
  private config = AuthConfigManager.getInstance().getConfig();
  private attemptTracker: Map<string, { count: number; lastAttempt: number; blocked?: number }> = new Map();

  constructor() {
    super();
    logger.info('Secure password strategy initialized', { strategy: this.name });
  }

  async authenticate(
    credentials: SecureCredentials,
    _page: Page,
    _context: BrowserContext,
  ): Promise<AuthenticationResult> {
    const sessionId = this.generateSessionId();

    try {
      logger.audit(
        'Authentication attempt',
        undefined,
        {
          email: credentials.email,
          hasPassword: !!credentials.password,
          strategy: this.name,
        },
        sessionId,
      );

      // Input validation
      const validationResult = this.validateCredentials(credentials);
      if (!validationResult.valid) {
        logger.security(
          'Invalid credentials format',
          {
            email: credentials.email,
            errors: validationResult.errors,
          },
          sessionId,
        );
        return {
          success: false,
          errorMessage: 'Invalid credentials format',
        };
      }

      // Rate limiting check
      if (!this.checkRateLimit(credentials.email, sessionId)) {
        return {
          success: false,
          errorMessage: 'Rate limit exceeded. Too many login attempts. Please try again later.',
        };
      }

      // Simulate authentication (in real app, this would call your API)
      const authResponse = await this.performAuthentication(credentials, sessionId);

      if (authResponse.success) {
        // Reset rate limiting on successful login
        this.resetRateLimit(credentials.email);

        // Generate secure JWT token
        const token = this.generateJWTToken(credentials.email, authResponse.userData!.role);
        const _refreshToken = this.generateRefreshToken();
        // Note: refresh token is generated for future use but not currently implemented
        void _refreshToken; // Suppress unused variable warning

        logger.audit(
          'Authentication successful',
          undefined,
          {
            email: credentials.email,
            role: authResponse.userData!.role,
          },
          sessionId,
        );

        return {
          success: true,
          token,
          userData: {
            ...authResponse.userData!,
            lastLogin: new Date(),
          },
          expiresAt: new Date(Date.now() + this.config.sessionTimeout * 1000),
        };
      } else {
        // Record failed attempt
        this.recordFailedAttempt(credentials.email);

        logger.security(
          'Authentication failed',
          {
            email: credentials.email,
            reason: authResponse.errorMessage,
          },
          sessionId,
        );

        return {
          success: false,
          errorMessage: authResponse.errorMessage || 'Authentication failed',
        };
      }
    } catch (error) {
      logger.error(
        'Authentication error',
        {
          email: credentials.email,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        sessionId,
      );

      return {
        success: false,
        errorMessage: 'Authentication system error',
      };
    }
  }

  async isValid(token?: string): Promise<boolean> {
    if (!token) {
      return false;
    }

    try {
      const decoded = jwt.verify(token, this.config.jwtSecret, {
        algorithms: ['HS256'],
        audience: this.config.testDomain,
        issuer: 'testwrightx-auth',
      }) as jwt.JwtPayload;

      // Check expiration
      if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) {
        logger.debug('Token expired during validation');
        return false;
      }

      // Check token age (additional security)
      if (decoded.iat && Date.now() / 1000 - decoded.iat > 24 * 60 * 60) {
        // 24 hours
        logger.security('Token too old, forcing re-authentication');
        return false;
      }

      return true;
    } catch (error) {
      logger.security('Invalid token during validation', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return false;
    }
  }

  public validateCredentials(credentials: SecureCredentials): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Email validation
    if (!credentials.email) {
      errors.push('Email is required');
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(credentials.email)) {
      errors.push('Invalid email format');
    }

    // Password validation
    if (!credentials.password) {
      errors.push('Password is required');
    } else if (credentials.password.length < 8) {
      errors.push('Password must be at least 8 characters');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  private checkRateLimit(email: string, sessionId: string): boolean {
    if (!this.config.rateLimiting.enabled) {
      return true;
    }

    const now = Date.now();
    const attempt = this.attemptTracker.get(email);

    if (!attempt) {
      return true;
    }

    // Check if user is blocked
    if (attempt.blocked && now < attempt.blocked) {
      logger.security(
        'User blocked due to rate limiting',
        {
          email,
          blockedUntil: new Date(attempt.blocked).toISOString(),
        },
        sessionId,
      );
      return false;
    }

    // Check if too many attempts in window
    const windowStart = now - this.config.rateLimiting.windowMs;
    if (attempt.lastAttempt > windowStart && attempt.count >= this.config.rateLimiting.maxAttempts) {
      // Block user
      attempt.blocked = now + this.config.rateLimiting.blockDuration;

      logger.security(
        'User blocked due to excessive attempts',
        {
          email,
          attempts: attempt.count,
          blockDuration: this.config.rateLimiting.blockDuration,
        },
        sessionId,
      );

      return false;
    }

    return true;
  }

  private recordFailedAttempt(email: string): void {
    const now = Date.now();
    const attempt = this.attemptTracker.get(email) || { count: 0, lastAttempt: 0 };

    // Reset count if outside window
    const windowStart = now - this.config.rateLimiting.windowMs;
    if (attempt.lastAttempt < windowStart) {
      attempt.count = 0;
    }

    attempt.count++;
    attempt.lastAttempt = now;

    this.attemptTracker.set(email, attempt);
  }

  private resetRateLimit(email: string): void {
    this.attemptTracker.delete(email);
  }

  private async performAuthentication(credentials: SecureCredentials, _sessionId: string): Promise<AuthResponse> {
    // Get expected credentials from config
    const personaCredentials = this.findPersonaCredentials(credentials.email);

    if (!personaCredentials) {
      return {
        success: false,
        errorMessage: 'User not found',
      };
    }

    // Simulate password verification (in real app, use bcrypt or similar)
    const passwordValid = await this.verifyPassword(credentials.password, personaCredentials.password);

    if (!passwordValid) {
      return {
        success: false,
        errorMessage: 'Invalid password',
      };
    }

    // Simulate MFA check (if required)
    if (this.requiresMFA(personaCredentials.role) && !credentials.mfaToken) {
      return {
        success: false,
        errorMessage: 'MFA token required',
        requiresMFA: true,
      };
    }

    return {
      success: true,
      userData: {
        email: credentials.email,
        role: personaCredentials.role,
        permissions: this.getRolePermissions(personaCredentials.role),
      },
    };
  }

  private findPersonaCredentials(email: string): { password: string; role: string } | null {
    const config = this.config;

    // Check admin credentials
    if (email === config.credentials.admin.email) {
      return {
        password: config.credentials.admin.password,
        role: config.credentials.admin.role,
      };
    }

    // Check customer credentials
    if (email === config.credentials.customer.email) {
      return {
        password: config.credentials.customer.password,
        role: config.credentials.customer.role,
      };
    }

    return null;
  }

  private async verifyPassword(provided: string, expected: string): Promise<boolean> {
    // In a real application, you would use bcrypt.compare() here
    // For testing purposes, we'll do a simple comparison
    // but add a small delay to simulate real password hashing
    await new Promise(resolve => setTimeout(resolve, 100));

    return provided === expected;
  }

  private requiresMFA(role: string): boolean {
    // Admin users require MFA in production
    return this.config.environment === 'production' && role === 'administrator';
  }

  private getRolePermissions(role: string): string[] {
    switch (role) {
      case 'administrator':
        return [
          'admin:read',
          'admin:write',
          'admin:delete',
          'users:read',
          'users:write',
          'users:delete',
          'reports:read',
          'reports:write',
          'settings:read',
          'settings:write',
          'audit:read',
        ];
      case 'customer':
        return ['profile:read', 'profile:write', 'orders:read', 'orders:write', 'support:read', 'support:write'];
      case 'guest':
        return ['public:read'];
      default:
        return [];
    }
  }

  private generateJWTToken(email: string, role: string): string {
    const payload = {
      email,
      role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.config.sessionTimeout,
      aud: this.config.testDomain,
      iss: 'testwrightx-auth',
      jti: this.generateSessionId(), // JWT ID for tracking
    };

    return jwt.sign(payload, this.config.jwtSecret, { algorithm: 'HS256' });
  }

  private generateRefreshToken(): string {
    return CryptoJS.lib.WordArray.random(32).toString();
  }

  private generateSessionId(): string {
    return CryptoJS.lib.WordArray.random(16).toString();
  }

  // Admin method to clear rate limiting (for testing)
  public clearRateLimiting(): void {
    this.attemptTracker.clear();
    logger.info('Rate limiting data cleared', { strategy: this.name });
  }

  // Get rate limiting status (for monitoring)
  public getRateLimitStatus(): Array<{ email: string; attempts: number; blocked: boolean }> {
    const now = Date.now();
    const status: Array<{ email: string; attempts: number; blocked: boolean }> = [];

    for (const [email, attempt] of this.attemptTracker) {
      status.push({
        email,
        attempts: attempt.count,
        blocked: !!(attempt.blocked && now < attempt.blocked),
      });
    }

    return status;
  }
}
