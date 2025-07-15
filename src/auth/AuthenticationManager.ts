import { PersonaManager } from '@auth/personas/PersonaManager';
import { UserPersona } from '@auth/personas/UserPersona';
import { SessionManager } from '@auth/session/SessionManager';
import { AuthenticationStrategyRegistry, IAuthenticationStrategy } from '@auth/strategies/base/AuthenticationStrategy';
import { BrowserContext, Page } from '@playwright/test';

// This tells us what information we get back after trying to log in
export interface AuthenticationResult {
  success: boolean;
  token?: string;
  userData?: any;
  errorMessage?: string;
  expiresAt?: Date;
}

// Re-export the AuthenticationResult for backwards compatibility
// The IAuthenticationStrategy interface is imported from base/AuthenticationStrategy

export class AuthenticationManager {
  // Manages our user types (admin, customer, guest)
  private personaManager: PersonaManager;

  // Remembers who's logged in
  private sessionManager: SessionManager;

  // Strategy registry for authentication methods
  private strategyRegistry: AuthenticationStrategyRegistry;

  // Who is currently logged in? (null = nobody)
  private currentUser: UserPersona | null = null;

  // Constructor - runs when we create a new AuthenticationManager
  constructor(
    // @ts-ignore - Reserved for future authentication strategy usage
    private readonly _page: Page,
    private readonly _context: BrowserContext,
  ) {
    // Note: page and context are stored for future authentication strategy usage
    // Set up our helper managers
    this.personaManager = new PersonaManager();
    this.sessionManager = new SessionManager(this._context);
    this.strategyRegistry = AuthenticationStrategyRegistry.getInstance();
  }

  // Register a new way to log in
  registerStrategy(strategy: IAuthenticationStrategy): void {
    this.strategyRegistry.register(strategy);
    console.log(`Added login method: ${strategy.name}`);
  }

  // Log in as a specific user type
  async authenticateAs(
    personaType: string, // Who to log in as: "admin", "customer", "guest"
    strategyName?: string, // How to log in: "password", "google" (optional)
    credentials?: any, // Login details (optional - we have defaults)
  ): Promise<boolean> {
    try {
      console.log(`Trying to log in as: ${personaType}`);

      // Step 1: Get the user type information
      const persona = this.personaManager.getPersona(personaType);
      if (!persona) {
        throw new Error(`Unknown user type: ${personaType}`);
      }

      // Step 2: Use default login method if none specified
      let strategy: IAuthenticationStrategy | undefined;
      if (strategyName) {
        strategy = this.strategyRegistry.get(strategyName);
      } else {
        strategy = this.strategyRegistry.getDefault();
        if (!strategy) {
          // Fall back to looking for 'secure-password' strategy
          strategy = this.strategyRegistry.get('secure-password');
        }
      }
      
      if (!strategy) {
        const loginMethod = strategyName ?? 'default';
        throw new Error(`Unknown login method: ${loginMethod}`);
      }

      // Step 3: Use default credentials if none provided
      const loginCredentials = credentials || persona.getDefaultCredentials();

      // Step 4: Check if we're already logged in as this user
      const existingSession = await this.sessionManager.getSession(personaType);
      if (existingSession && (await strategy.isValid(existingSession.token))) {
        console.log(`Already logged in as ${personaType} - reusing session!`);
        await this.sessionManager.restoreSession(existingSession);
        this.currentUser = persona;
        return true;
      }

      // Step 5: Actually do the login
      console.log(`Logging in as ${personaType}...`);
      const result = await strategy.authenticate(loginCredentials, this._page, this._context);

      if (result.success) {
        // Save the login session for next time
        await this.sessionManager.saveSession({
          personaType,
          token: result.token!,
          userData: result.userData,
          expiresAt: result.expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000),
        });

        this.currentUser = persona;
        console.log(`Successfully logged in as ${personaType}`);
        return true;
      } else {
        console.error(`Login failed: ${result.errorMessage}`);
        return false;
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error(`Login error: ${errorMessage}`);
      return false;
    }
  }

  // Who is currently logged in?
  getCurrentUser(): UserPersona | null {
    return this.currentUser;
  }

  // Is anyone logged in right now?
  isAuthenticated(): boolean {
    return this.currentUser !== null;
  }

  // Logout the current user
  async logout(): Promise<void> {
    if (this.currentUser) {
      await this.sessionManager.clearSession();
      this.currentUser = null;
      console.log('Logged out successfully');
    }
  }

  // Switch to a different user (if we have a saved session)
  async switchPersona(newPersonaType: string): Promise<boolean> {
    const newPersona = this.personaManager.getPersona(newPersonaType);
    if (!newPersona) {
      console.error(`Unknown user type: ${newPersonaType}`);
      return false;
    }

    // Try to use an existing session
    const existingSession = await this.sessionManager.getSession(newPersonaType);
    if (existingSession) {
      await this.sessionManager.restoreSession(existingSession);
      this.currentUser = newPersona;
      console.log(`Switched to ${newPersonaType}`);
      return true;
    }

    console.log(`No saved session for ${newPersonaType} - need to do full login`);
    return false;
  }
}
