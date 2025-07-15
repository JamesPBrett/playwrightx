import { Page } from '@playwright/test';
import { UserPersona, PersonaCapabilities, PersonaCredentials } from '@auth/personas/UserPersona';
import { AuthConfigManager } from '@auth/config/AuthConfig';
import { logger } from '@auth/utils/SecureLogger';

/**
 * Admin Persona - The "root user" with all permissions
 * This persona represents a system administrator with full access.
 * Admins can manage users, view all reports, modify system settings, and access the admin
 * panel.
 * They can also delete data and perform system-wide operations.
 */
export class AdminPersona extends UserPersona {
  constructor() {
    const config = AuthConfigManager.getInstance().getConfig();

    // Define what an admin can do (all permissions!)
    const capabilities: PersonaCapabilities = {
      canViewAdminPanel: true,
      canManageUsers: true,
      canAccessReports: true,
      canModifySettings: true,
      canDeleteData: true,
      maxFileUploadSize: 100,
      allowedFeatures: ['admin-panel', 'user-management', 'system-settings', 'reports', 'data-export', 'audit-logs'],
    };

    // Get admin credentials from secure configuration
    const credentials: PersonaCredentials = {
      email: config.credentials.admin.email,
      password: config.credentials.admin.password,
      role: config.credentials.admin.role,
    };

    // Extra test data for admin scenarios
    const testData = {
      department: 'IT',
      permissions: 'full-access',
      preferredTheme: 'dark',
      notifications: 'all',
    };

    // Call parent constructor with admin data
    super('Admin', capabilities, credentials, testData);
  }

  /**
   * Where does admin land after login?
   */
  getExpectedLandingPage(): string {
    return '/admin/dashboard'; // Admins go to admin dashboard
  }

  /**
   * What menu items should admin see?
   */
  getExpectedNavigationItems(): string[] {
    return [
      'Dashboard',
      'Users', // User management
      'Reports', // All reports
      'Settings', // System settings
      'Admin Panel', // Admin-only section
      'Audit Logs', // Security logs
      'System Health', // System monitoring
    ];
  }

  /**
   * This checks the page to make sure admin login worked
   */
  async validateAuthentication(page: Page): Promise<boolean> {
    try {
      // Wait for page to finish loading
      await page.waitForLoadState('networkidle');

      // Check 1: Admin panel link should be visible
      const adminPanelLink = page.locator('[data-testid="admin-panel-link"]');
      await adminPanelLink.waitFor({ timeout: 5000 });

      // Check 2: User management section should be visible
      const userManagementSection = page.locator('[data-testid="user-management"]');
      const isUserManagementVisible = await userManagementSection.isVisible();

      // Check 3: Admin badge should be visible in user profile
      const adminBadge = page.locator('[data-testid="admin-badge"]');
      const hasAdminBadge = await adminBadge.isVisible();

      // Check 4: URL should contain admin path
      const currentUrl = page.url();
      const isOnAdminPage = currentUrl.includes('/admin');

      // All checks must pass for successful validation
      const isValid = isUserManagementVisible && hasAdminBadge && isOnAdminPage;

      if (isValid) {
        logger.info('Admin authentication validated successfully', {
          userManagementVisible: isUserManagementVisible,
          adminBadgePresent: hasAdminBadge,
          onAdminPage: isOnAdminPage,
        });
      } else {
        logger.warn('Admin authentication validation failed', {
          userManagementVisible: isUserManagementVisible,
          adminBadgePresent: hasAdminBadge,
          onAdminPage: isOnAdminPage,
          currentUrl,
        });
      }

      return isValid;
    } catch (error) {
      logger.error('Admin authentication validation failed', {
        error: error instanceof Error ? error.message : String(error),
        currentUrl: page.url(),
      });
      return false;
    }
  }
}
