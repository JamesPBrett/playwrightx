import { Page } from '@playwright/test';
import { UserPersona, PersonaCapabilities, PersonaCredentials } from '@auth/personas/UserPersona';
import { AuthConfigManager } from '@auth/config/AuthConfig';
import { logger } from '@auth/utils/SecureLogger';

/**
 * Guest Persona - Non-logged-in user
 * This persona represents a guest user with very limited capabilities.
 * Guests can view public content but cannot access any authenticated features.
 */
export class GuestPersona extends UserPersona {
  constructor() {
    const config = AuthConfigManager.getInstance().getConfig();

    // Define what a guest can do (very limited!)
    const capabilities: PersonaCapabilities = {
      canViewAdminPanel: false,
      canManageUsers: false,
      canAccessReports: false,
      canModifySettings: false,
      canDeleteData: false,
      maxFileUploadSize: 0,
      allowedFeatures: ['product-catalog', 'contact-form', 'registration', 'login'],
    };

    // Get guest credentials from secure configuration
    const credentials: PersonaCredentials = {
      email: config.credentials.guest.email,
      password: config.credentials.guest.password,
      role: config.credentials.guest.role,
    };

    // Guest-specific test data
    const testData = {
      sessionId: 'guest-session',
      browsingHistory: [],
      cartItems: [],
    };

    super('Guest', capabilities, credentials, testData);
  }

  getExpectedLandingPage(): string {
    return '/'; // Home page for guests
  }

  getExpectedNavigationItems(): string[] {
    return [
      'Home',
      'Products',
      'About',
      'Contact',
      'Login', // Should see login option
      'Register', // Should see register option
    ];
  }

  async validateAuthentication(page: Page): Promise<boolean> {
    try {
      await page.waitForLoadState('networkidle');

      // Login button should be visible for guests
      const loginButton = page.locator('[data-testid="login-button"]');
      await loginButton.waitFor({ timeout: 5000 });

      // User profile should NOT be visible
      const userProfile = page.locator('[data-testid="user-profile"]');
      const profileVisible = await userProfile.isVisible().catch(() => false);

      // Should NOT be on authenticated pages
      const currentUrl = page.url();
      const notOnAuthenticatedPage = !currentUrl.includes('/dashboard') && !currentUrl.includes('/admin');

      const isValid = !profileVisible && notOnAuthenticatedPage;

      if (isValid) {
        logger.info('Guest state validated successfully', {
          profileHidden: !profileVisible,
          notOnAuthenticatedPage,
        });
      } else {
        logger.warn('Guest state validation failed', {
          profileVisible,
          notOnAuthenticatedPage,
          currentUrl,
        });
      }

      return isValid;
    } catch (error) {
      logger.error('Guest validation failed', {
        error: error instanceof Error ? error.message : String(error),
        currentUrl: page.url(),
      });
      return false;
    }
  }
}
