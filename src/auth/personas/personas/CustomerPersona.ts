import { Page } from '@playwright/test';
import { UserPersona, PersonaCapabilities, PersonaCredentials } from '@auth/personas/UserPersona';
import { AuthConfigManager } from '@auth/config/AuthConfig';
import { logger } from '@auth/utils/SecureLogger';

/**
 * Customer Persona - Regular application user
 * This persona represents a customer with limited permissions.
 * Customers can access their own data, view reports, and manage their profile.
 * They cannot access admin features or manage other users.
 */
export class CustomerPersona extends UserPersona {
  constructor() {
    const config = AuthConfigManager.getInstance().getConfig();

    // Define what a customer can do (limited permissions)
    const capabilities: PersonaCapabilities = {
      canViewAdminPanel: false, // No admin panel access
      canManageUsers: false, // Cannot manage other users
      canAccessReports: true, // Can see their own reports
      canModifySettings: false, // Cannot modify system settings
      canDeleteData: false, // Cannot delete system data (only their own)
      maxFileUploadSize: 10, // Can upload 10MB files
      allowedFeatures: ['profile-management', 'purchase-history', 'personal-reports', 'customer-support'],
    };

    // Get customer credentials from secure configuration
    const credentials: PersonaCredentials = {
      email: config.credentials.customer.email,
      password: config.credentials.customer.password,
      role: config.credentials.customer.role,
    };

    // Customer-specific test data
    const testData = {
      customerId: 'CUST-001',
      membershipLevel: 'standard',
      preferredPaymentMethod: 'credit-card',
      shippingAddress: {
        street: '123 Test Street',
        city: 'Test City',
        zipCode: '12345',
      },
    };

    super('Customer', capabilities, credentials, testData);
  }

  getExpectedLandingPage(): string {
    return '/dashboard'; // Regular user dashboard
  }

  getExpectedNavigationItems(): string[] {
    return ['Dashboard', 'My Orders', 'Profile', 'Support', 'Account Settings'];
  }

  async validateAuthentication(page: Page): Promise<boolean> {
    try {
      await page.waitForLoadState('networkidle');

      // Admin panel should NOT be visible to customers
      const adminPanelLink = page.locator('[data-testid="admin-panel-link"]');
      const adminPanelVisible = await adminPanelLink.isVisible().catch(() => false);

      // Customer dashboard should be visible
      const customerDashboard = page.locator('[data-testid="customer-dashboard"]');
      await customerDashboard.waitFor({ timeout: 5000 });

      // Customer badge should be present
      const customerBadge = page.locator('[data-testid="customer-badge"]');
      const hasCustomerBadge = await customerBadge.isVisible();

      // Should NOT be on admin pages
      const currentUrl = page.url();
      const notOnAdminPage = !currentUrl.includes('/admin');

      const isValid = !adminPanelVisible && hasCustomerBadge && notOnAdminPage;

      if (isValid) {
        logger.info('Customer authentication validated successfully', {
          adminPanelHidden: !adminPanelVisible,
          customerBadgePresent: hasCustomerBadge,
          notOnAdminPage,
        });
      } else {
        logger.warn('Customer authentication validation failed', {
          adminPanelVisible,
          customerBadgePresent: hasCustomerBadge,
          notOnAdminPage,
          currentUrl,
        });
      }

      return isValid;
    } catch (error) {
      logger.error('Customer authentication validation failed', {
        error: error instanceof Error ? error.message : String(error),
        currentUrl: page.url(),
      });
      return false;
    }
  }
}
