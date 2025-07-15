import { BrowserContext } from '@playwright/test';

export interface AuthSession {
  personaType: string;
  token: string;
  userData?: any;
  expiresAt: Date;
  createdAt: Date;
}

export class SessionManager {
  // In-memory storage for quick access to sessions
  private sessions: Map<string, AuthSession> = new Map();

  constructor(private context: BrowserContext) {
    // Initialize the session manager with the browser context
  }

  // Save a login session for reuse
  async saveSession(session: Omit<AuthSession, 'createdAt'>): Promise<void> {
    // Step 1: Add the creation timestamp
    const fullSession: AuthSession = {
      ...session,
      createdAt: new Date(), // When we saved this session
    };

    // Step 2: Store in memory for fast access
    this.sessions.set(session.personaType, fullSession);
    console.log(`Saved session for: ${session.personaType}`);

    // Step 3: Store in browser cookies (survives browser restarts)
    await this.context.addCookies([
      {
        name: `testwrightx_session_${session.personaType}`,
        value: this.encodeSession(fullSession),
        domain: 'localhost', // Adjust this for your test environment
        path: '/',
        httpOnly: false,
        secure: false,
        expires: Math.floor(session.expiresAt.getTime() / 1000),
      },
    ]);

    // Step 4: Store in localStorage (for Single Page Applications)
    await this.context.addInitScript(sessionData => {
      localStorage.setItem(
        `testwrightx_auth_${sessionData.personaType}`,
        JSON.stringify({
          token: sessionData.token,
          userData: sessionData.userData,
          expiresAt: sessionData.expiresAt,
        }),
      );
    }, session);
  }

  // Get a saved session for a user type
  async getSession(personaType: string): Promise<AuthSession | null> {
    // Step 1: Check memory first (fastest)
    let session = this.sessions.get(personaType);

    if (!session) {
      // Step 2: Check browser cookies if not in memory
      const cookies = await this.context.cookies();
      const sessionCookie = cookies.find(c => c.name === `testwrightx_session_${personaType}`);

      if (sessionCookie) {
        try {
          // Decode the session from the cookie
          session = this.decodeSession(sessionCookie.value);
          this.sessions.set(personaType, session); // Put it back in memory
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          console.warn(`Couldn't read session for ${personaType}: ${errorMessage}`);
          return null;
        }
      }
    }

    // Step 3: Check if the session is still valid (not expired)
    if (session && this.isSessionValid(session)) {
      return session;
    }

    // Step 4: Session is expired or doesn't exist
    if (session) {
      console.log(`Session expired for: ${personaType}`);
      await this.clearSession(personaType); // Clean up expired session
    }

    return null;
  }

  // Restore a session to the browser
  async restoreSession(session: AuthSession): Promise<void> {
    console.log(`Restoring session for: ${session.personaType}`);

    // Step 1: Put authentication tokens in localStorage
    // (This is where most web apps look for login tokens)
    await this.context.addInitScript(sessionData => {
      localStorage.setItem('authToken', sessionData.token);
      localStorage.setItem('userData', JSON.stringify(sessionData.userData));
    }, session);

    // Step 2: Set authentication cookies
    // (Some apps use cookies instead of localStorage)
    await this.context.addCookies([
      {
        name: 'auth_token',
        value: session.token,
        domain: 'localhost', // Adjust for your app
        path: '/',
        httpOnly: true,
        secure: false,
      },
    ]);

    console.log(`Session restored for: ${session.personaType}`);
  }

  // Clear sessions (logout)
  async clearSession(personaType?: string): Promise<void> {
    if (personaType) {
      // Clear specific user session
      this.sessions.delete(personaType);

      await this.context.addInitScript(persona => {
        localStorage.removeItem(`testwrightx_auth_${persona}`);
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
      }, personaType);

      console.log(`Cleared session for: ${personaType}`);
    } else {
      // Clear ALL sessions
      this.sessions.clear();

      await this.context.addInitScript(() => {
        // Remove all authentication-related items
        Object.keys(localStorage).forEach(key => {
          if (key.startsWith('testwrightx_auth_') || key === 'authToken' || key === 'userData') {
            localStorage.removeItem(key);
          }
        });
      });

      console.log('Cleared all sessions');
    }
  }

  // Check if a session is still valid (not expired)
  private isSessionValid(session: AuthSession): boolean {
    return new Date() < session.expiresAt;
  }

  // Encode session data for safe storage in cookies
  private encodeSession(session: AuthSession): string {
    return Buffer.from(JSON.stringify(session)).toString('base64');
  }

  // Decode session data from cookies
  private decodeSession(encoded: string): AuthSession {
    const decoded = Buffer.from(encoded, 'base64').toString('utf-8');
    const parsed = JSON.parse(decoded);

    // Convert date strings back to actual Date objects
    parsed.expiresAt = new Date(parsed.expiresAt);
    parsed.createdAt = new Date(parsed.createdAt);

    return parsed;
  }
}
