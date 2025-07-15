import { BrowserContext } from '@playwright/test';
import CryptoJS from 'crypto-js';
import jwt from 'jsonwebtoken';
import { AuthConfigManager } from '@auth/config/AuthConfig';
import { logger } from '@auth/utils/SecureLogger';

export interface AuthSession {
  personaType: string;
  token: string;
  userData?: any;
  expiresAt: Date;
  createdAt: Date;
  csrfToken?: string;
  refreshToken?: string;
  lastActivity: Date;
}

export interface TokenPayload {
  persona: string;
  role: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
}

/**
 * Enhanced session manager with encryption, JWT validation, and security features
 */
export class SecureSessionManager {
  private sessions: Map<string, AuthSession> = new Map();
  private config = AuthConfigManager.getInstance().getConfig();
  private sessionId: string;

  // Rate limiting tracking
  private attemptHistory: Map<string, number[]> = new Map();
  private blockedUsers: Map<string, number> = new Map();

  constructor(private context: BrowserContext) {
    this.sessionId = this.generateSessionId();
    logger.info('Session manager initialized', { sessionId: this.sessionId });
  }

  private generateSessionId(): string {
    return CryptoJS.lib.WordArray.random(16).toString();
  }

  private generateCSRFToken(): string {
    return CryptoJS.lib.WordArray.random(this.config.csrf.tokenLength / 2).toString();
  }

  private createJWTToken(persona: string, role: string): string {
    const payload: TokenPayload = {
      persona,
      role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.config.sessionTimeout,
      aud: this.config.testDomain,
      iss: 'testwrightx-auth',
    };

    return jwt.sign(payload, this.config.jwtSecret, { algorithm: 'HS256' });
  }

  private validateJWTToken(token: string): TokenPayload | null {
    try {
      const decoded = jwt.verify(token, this.config.jwtSecret, {
        algorithms: ['HS256'],
        audience: this.config.testDomain,
        issuer: 'testwrightx-auth',
      }) as TokenPayload;

      // Check if token is expired
      if (decoded.exp < Math.floor(Date.now() / 1000)) {
        logger.warn('JWT token has expired', { persona: decoded.persona }, this.sessionId);
        return null;
      }

      return decoded;
    } catch (error) {
      logger.security(
        'Invalid JWT token detected',
        {
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );
      return null;
    }
  }

  private encryptSessionData(data: string): string {
    try {
      return CryptoJS.AES.encrypt(data, this.config.sessionEncryptionKey).toString();
    } catch (error) {
      logger.error(
        'Failed to encrypt session data',
        {
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );
      throw new Error('Session encryption failed');
    }
  }

  private decryptSessionData(encryptedData: string): string {
    try {
      const bytes = CryptoJS.AES.decrypt(encryptedData, this.config.sessionEncryptionKey);
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);

      if (!decrypted) {
        throw new Error('Decryption resulted in empty string');
      }

      return decrypted;
    } catch (error) {
      logger.security(
        'Failed to decrypt session data - possible tampering',
        {
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );
      throw new Error('Session decryption failed');
    }
  }

  private checkRateLimit(personaType: string): boolean {
    if (!this.config.rateLimiting.enabled) {
      return true;
    }

    const now = Date.now();
    const attempts = this.attemptHistory.get(personaType) || [];

    // Check if user is currently blocked
    const blockUntil = this.blockedUsers.get(personaType);
    if (blockUntil && now < blockUntil) {
      logger.security(
        'Rate limit exceeded - user blocked',
        {
          persona: personaType,
          blockedUntil: new Date(blockUntil).toISOString(),
        },
        this.sessionId,
      );
      return false;
    }

    // Clean up old attempts (outside the window)
    const windowStart = now - this.config.rateLimiting.windowMs;
    const recentAttempts = attempts.filter(timestamp => timestamp > windowStart);

    // Check if too many attempts
    if (recentAttempts.length >= this.config.rateLimiting.maxAttempts) {
      const blockUntil = now + this.config.rateLimiting.blockDuration;
      this.blockedUsers.set(personaType, blockUntil);

      logger.security(
        'Rate limit exceeded - blocking user',
        {
          persona: personaType,
          attempts: recentAttempts.length,
          blockDuration: this.config.rateLimiting.blockDuration,
        },
        this.sessionId,
      );

      return false;
    }

    // Record this attempt
    recentAttempts.push(now);
    this.attemptHistory.set(personaType, recentAttempts);

    return true;
  }

  private updateActivity(session: AuthSession): void {
    session.lastActivity = new Date();
  }

  async saveSession(sessionData: Omit<AuthSession, 'createdAt' | 'lastActivity' | 'csrfToken'>): Promise<void> {
    try {
      // Check rate limiting
      if (!this.checkRateLimit(sessionData.personaType)) {
        throw new Error('Rate limit exceeded. Please try again later.');
      }

      // Create full session with security tokens
      const fullSession: AuthSession = {
        ...sessionData,
        createdAt: new Date(),
        lastActivity: new Date(),
        refreshToken: CryptoJS.lib.WordArray.random(32).toString(),
      };

      // Add CSRF token if enabled
      if (this.config.csrf.enabled) {
        fullSession.csrfToken = this.generateCSRFToken();
      }

      // Store in memory
      this.sessions.set(sessionData.personaType, fullSession);

      // Encrypt session data for storage
      const sessionJson = JSON.stringify({
        ...fullSession,
        expiresAt: fullSession.expiresAt.toISOString(),
        createdAt: fullSession.createdAt.toISOString(),
        lastActivity: fullSession.lastActivity.toISOString(),
      });

      const encryptedSession = this.encryptSessionData(sessionJson);

      // Store in secure cookies
      await this.context.addCookies([
        {
          name: `testwrightx_session_${sessionData.personaType}`,
          value: encryptedSession,
          domain: this.config.testDomain,
          path: '/',
          httpOnly: this.config.cookieHttpOnly,
          secure: this.config.cookieSecure,
          expires: Math.floor(sessionData.expiresAt.getTime() / 1000),
          sameSite: 'Strict',
        },
      ]);

      // Store authentication tokens in browser storage
      const initScriptData: {
        token: string;
        personaType: string;
        expiresAt: string;
        csrfToken?: string;
        userData?: any;
      } = {
        token: fullSession.token,
        personaType: sessionData.personaType,
        expiresAt: sessionData.expiresAt.toISOString(),
        userData: sessionData.userData,
      };

      if (fullSession.csrfToken) {
        initScriptData.csrfToken = fullSession.csrfToken;
      }

      await this.context.addInitScript(sessionInfo => {
        // Set auth token in localStorage
        localStorage.setItem('authToken', sessionInfo.token);
        localStorage.setItem('tokenType', 'Bearer');
        localStorage.setItem('expiresAt', sessionInfo.expiresAt);

        // Set CSRF token if enabled
        if (sessionInfo.csrfToken) {
          localStorage.setItem('csrfToken', sessionInfo.csrfToken);
        }

        // Set user data (non-sensitive)
        localStorage.setItem(
          'userData',
          JSON.stringify({
            persona: sessionInfo.personaType,
            role: sessionInfo.userData?.role || 'user',
          }),
        );
      }, initScriptData);

      logger.audit(
        'Session saved',
        sessionData.personaType,
        {
          hasCSRF: !!fullSession.csrfToken,
          expiresAt: fullSession.expiresAt.toISOString(),
        },
        this.sessionId,
      );
    } catch (error) {
      logger.error(
        'Failed to save session',
        {
          persona: sessionData.personaType,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );
      throw error;
    }
  }

  async getSession(personaType: string): Promise<AuthSession | null> {
    try {
      // Check memory first
      let session = this.sessions.get(personaType);

      if (!session) {
        // Try to retrieve from cookies
        const cookies = await this.context.cookies();
        const sessionCookie = cookies.find(c => c.name === `testwrightx_session_${personaType}`);

        if (sessionCookie?.value) {
          try {
            const decryptedData = this.decryptSessionData(sessionCookie.value);
            const sessionData = JSON.parse(decryptedData);

            // Reconstruct Date objects
            const reconstructedSession: AuthSession = {
              ...sessionData,
              expiresAt: new Date(sessionData.expiresAt),
              createdAt: new Date(sessionData.createdAt),
              lastActivity: new Date(sessionData.lastActivity),
            };

            // Store back in memory
            session = reconstructedSession;
            this.sessions.set(personaType, session);
          } catch (error) {
            logger.security(
              'Failed to decrypt session cookie - possible tampering',
              {
                persona: personaType,
                error: error instanceof Error ? error.message : 'Unknown error',
              },
              this.sessionId,
            );
            return null;
          }
        }
      }

      if (!session) {
        return null;
      }

      // Validate session
      if (!this.isSessionValid(session)) {
        logger.info('Session expired or invalid', { persona: personaType }, this.sessionId);
        await this.clearSession(personaType);
        return null;
      }

      // Update activity timestamp
      this.updateActivity(session);

      return session;
    } catch (error) {
      logger.error(
        'Failed to retrieve session',
        {
          persona: personaType,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );
      return null;
    }
  }

  async restoreSession(session: AuthSession): Promise<void> {
    try {
      logger.audit('Restoring session', session.personaType, {}, this.sessionId);

      // Validate JWT token
      const tokenPayload = this.validateJWTToken(session.token);
      if (!tokenPayload) {
        throw new Error('Invalid or expired token');
      }

      // Update activity
      this.updateActivity(session);

      // Set authentication in browser
      await this.context.addInitScript(
        authData => {
          // Set authentication tokens
          localStorage.setItem('authToken', authData.token);
          localStorage.setItem('tokenType', 'Bearer');
          localStorage.setItem('expiresAt', authData.expiresAt);
          localStorage.setItem('userData', JSON.stringify(authData.userData));

          // Set CSRF token if available
          if (authData.csrfToken) {
            localStorage.setItem('csrfToken', authData.csrfToken);
            // Also set as meta tag for forms
            const csrfMeta = document.createElement('meta');
            csrfMeta.name = 'csrf-token';
            csrfMeta.content = authData.csrfToken;
            document.head.appendChild(csrfMeta);
          }
        },
        {
          token: session.token,
          csrfToken: session.csrfToken,
          expiresAt: session.expiresAt.toISOString(),
          userData: session.userData,
        },
      );

      // Set authentication cookies
      await this.context.addCookies([
        {
          name: 'auth_token',
          value: session.token,
          domain: this.config.testDomain,
          path: '/',
          httpOnly: this.config.cookieHttpOnly,
          secure: this.config.cookieSecure,
          sameSite: 'Strict',
        },
      ]);

      logger.audit(
        'Session restored successfully',
        session.personaType,
        {
          tokenValid: true,
          hasCSRF: !!session.csrfToken,
        },
        this.sessionId,
      );
    } catch (error) {
      logger.error(
        'Failed to restore session',
        {
          persona: session.personaType,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );
      throw error;
    }
  }

  async clearSession(personaType?: string): Promise<void> {
    try {
      if (personaType) {
        // Clear specific session
        this.sessions.delete(personaType);

        await this.context.addInitScript(persona => {
          // Remove auth tokens
          localStorage.removeItem(`testwrightx_auth_${persona}`);
          localStorage.removeItem('authToken');
          localStorage.removeItem('tokenType');
          localStorage.removeItem('userData');
          localStorage.removeItem('csrfToken');
          localStorage.removeItem('expiresAt');

          // Remove CSRF meta tag
          const csrfMeta = document.querySelector('meta[name="csrf-token"]');
          if (csrfMeta) {
            csrfMeta.remove();
          }
        }, personaType);

        logger.audit('Session cleared', personaType, {}, this.sessionId);
      } else {
        // Clear all sessions
        this.sessions.clear();
        this.attemptHistory.clear();
        this.blockedUsers.clear();

        await this.context.addInitScript(() => {
          // Remove all auth-related items
          const keysToRemove = [];
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (
              key &&
              (key.startsWith('testwrightx_auth_') ||
                key === 'authToken' ||
                key === 'tokenType' ||
                key === 'userData' ||
                key === 'csrfToken' ||
                key === 'expiresAt')
            ) {
              keysToRemove.push(key);
            }
          }
          keysToRemove.forEach(key => localStorage.removeItem(key));

          // Remove CSRF meta tag
          const csrfMeta = document.querySelector('meta[name="csrf-token"]');
          if (csrfMeta) {
            csrfMeta.remove();
          }
        });

        logger.audit('All sessions cleared', undefined, {}, this.sessionId);
      }
    } catch (error) {
      logger.error(
        'Failed to clear session',
        {
          persona: personaType,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );
      throw error;
    }
  }

  private isSessionValid(session: AuthSession): boolean {
    const now = new Date();

    // Check expiration
    if (now >= session.expiresAt) {
      return false;
    }

    // Validate JWT token
    const tokenPayload = this.validateJWTToken(session.token);
    if (!tokenPayload) {
      return false;
    }

    // Check if session is too old (security measure)
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    if (now.getTime() - session.createdAt.getTime() > maxAge) {
      logger.security(
        'Session exceeded maximum age',
        {
          persona: session.personaType,
          age: now.getTime() - session.createdAt.getTime(),
        },
        this.sessionId,
      );
      return false;
    }

    return true;
  }

  async refreshSession(personaType: string): Promise<boolean> {
    try {
      const session = await this.getSession(personaType);
      if (!session) {
        return false;
      }

      // Create new token with extended expiration
      const newToken = this.createJWTToken(personaType, session.userData?.role || 'user');
      const newExpiration = new Date(Date.now() + this.config.sessionTimeout * 1000);

      // Update session
      session.token = newToken;
      session.expiresAt = newExpiration;
      session.refreshToken = CryptoJS.lib.WordArray.random(32).toString();

      await this.saveSession({
        personaType: session.personaType,
        token: session.token,
        userData: session.userData,
        expiresAt: session.expiresAt,
      });

      logger.audit(
        'Session refreshed',
        personaType,
        {
          newExpiresAt: newExpiration.toISOString(),
        },
        this.sessionId,
      );

      return true;
    } catch (error) {
      logger.error(
        'Failed to refresh session',
        {
          persona: personaType,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );
      return false;
    }
  }

  getSessionInfo(): { activeUsers: string[]; sessionCount: number; sessionId: string } {
    return {
      activeUsers: Array.from(this.sessions.keys()),
      sessionCount: this.sessions.size,
      sessionId: this.sessionId,
    };
  }
}
