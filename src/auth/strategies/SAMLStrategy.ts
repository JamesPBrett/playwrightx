import { Page, BrowserContext } from '@playwright/test';
import jwt from 'jsonwebtoken';
import CryptoJS from 'crypto-js';
import {
  BaseAuthenticationStrategy,
  AuthenticationCredentials,
  AuthenticationResult,
  AuthenticationFlow,
  UserData,
} from '@auth/strategies/base/AuthenticationStrategy';
import { AuthConfigManager } from '@auth/config/AuthConfig';
import { logger } from '@auth/utils/SecureLogger';

export interface SAMLCredentials extends AuthenticationCredentials {
  username: string;
  password: string;
  idpUrl?: string;
  spEntityId?: string;
  nameIdFormat?: string;
  attributeMapping?: Record<string, string>;
}

export interface SAMLConfig {
  idpUrl: string;
  spEntityId: string;
  spAcsUrl: string; // Assertion Consumer Service URL
  nameIdFormat: string;
  certificateFingerprint?: string;
  signAuthnRequests?: boolean;
  wantAssertionsSigned?: boolean;
  attributeMapping: Record<string, string>;
}

/**
 * SAML authentication strategy
 * Simulates SAML SSO flow for testing
 */
export class SAMLStrategy extends BaseAuthenticationStrategy {
  public readonly name = 'saml';
  public readonly type = 'saml' as const;
  public readonly provider: string;

  private config: SAMLConfig;
  private authConfig = AuthConfigManager.getInstance().getConfig();

  constructor(provider: string, config: SAMLConfig) {
    super();
    this.provider = provider;
    this.config = config;

    logger.info('SAML strategy initialized', {
      provider: this.provider,
      idpUrl: config.idpUrl,
      spEntityId: config.spEntityId,
    });
  }

  public async authenticate(
    credentials: SAMLCredentials,
    page: Page,
    _context: BrowserContext,
  ): Promise<AuthenticationResult> {
    try {
      logger.audit(
        'SAML authentication started',
        undefined,
        {
          provider: this.provider,
          username: credentials.username,
        },
        this.sessionId,
      );

      // Validate credentials
      const validation = this.validateCredentials(credentials);
      if (!validation.valid) {
        return {
          success: false,
          errorMessage: `Invalid credentials: ${validation.errors.join(', ')}`,
        };
      }

      // Step 1: Generate SAML AuthnRequest
      const authnRequest = this.generateAuthnRequest();

      // Step 2: Redirect to IdP with SAML request
      const idpUrl = this.buildIdpUrl(authnRequest);
      await page.goto(idpUrl);

      // Step 3: Handle IdP login
      const loginResult = await this.handleIdpLogin(page, credentials);
      if (!loginResult.success) {
        return loginResult;
      }

      // Step 4: Wait for SAML response at ACS
      const samlResponse = await this.waitForSAMLResponse(page);
      if (!samlResponse) {
        return {
          success: false,
          errorMessage: 'Failed to receive SAML response',
        };
      }

      // Step 5: Process SAML response
      const responseData = this.processSAMLResponse(samlResponse);
      if (!responseData.valid) {
        return {
          success: false,
          errorMessage: responseData.error || 'Invalid SAML response',
        };
      }

      // Step 6: Extract user data from SAML assertions
      const userData = this.extractUserDataFromSAML(responseData.assertions || {});

      // Step 7: Generate JWT token
      const token = this.generateJWTToken(userData);

      logger.audit(
        'SAML authentication successful',
        undefined,
        {
          provider: this.provider,
          userId: userData.id,
          nameId: responseData.nameId,
        },
        this.sessionId,
      );

      return {
        success: true,
        token,
        userData,
        expiresAt: new Date(Date.now() + this.authConfig.sessionTimeout * 1000),
      };
    } catch (error) {
      logger.error(
        'SAML authentication failed',
        {
          provider: this.provider,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );

      return {
        success: false,
        errorMessage: `SAML authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  public async isValid(token?: string): Promise<boolean> {
    if (!token) {
      return false;
    }

    try {
      const decoded = jwt.verify(token, this.authConfig.jwtSecret) as jwt.JwtPayload;

      // Check expiration
      if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) {
        return false;
      }

      // Check that it's a SAML token
      if (decoded.authType !== 'saml') {
        return false;
      }

      // Check provider
      if (decoded.provider !== this.provider) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  public getAuthenticationFlow(credentials: SAMLCredentials): AuthenticationFlow {
    return {
      steps: [
        {
          type: 'redirect',
          url: this.buildIdpUrl(this.generateAuthnRequest()),
        },
        {
          type: 'form',
          selector: this.getIdpLoginFormSelector(),
          data: {
            username: credentials.username,
            password: credentials.password,
          },
        },
        {
          type: 'wait',
          waitFor: this.config.spAcsUrl,
        },
      ],
      finalRedirect: this.config.spAcsUrl,
      successIndicators: ['SAMLResponse='],
      failureIndicators: ['error=', 'SAMLError='],
    };
  }

  public validateCredentials(credentials: SAMLCredentials): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!credentials.username) {
      errors.push('Username is required');
    }

    if (!credentials.password) {
      errors.push('Password is required');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  private generateAuthnRequest(): string {
    const requestId = '_' + CryptoJS.lib.WordArray.random(16).toString();
    const issueInstant = new Date().toISOString();

    // Simplified SAML AuthnRequest (in real scenario, use proper XML library)
    const authnRequest = `
      <samlp:AuthnRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="${requestId}"
        IssueInstant="${issueInstant}"
        Version="2.0"
        Destination="${this.config.idpUrl}"
        AssertionConsumerServiceURL="${this.config.spAcsUrl}"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
        
        <saml:Issuer>${this.config.spEntityId}</saml:Issuer>
        
        <samlp:NameIDPolicy
          Format="${this.config.nameIdFormat}"
          AllowCreate="true"/>
      </samlp:AuthnRequest>
    `.trim();

    // Base64 encode the request
    return Buffer.from(authnRequest).toString('base64');
  }

  private buildIdpUrl(authnRequest: string): string {
    const params = new URLSearchParams({
      SAMLRequest: authnRequest,
      RelayState: this.generateRelayState(),
    });

    return `${this.config.idpUrl}?${params.toString()}`;
  }

  private async handleIdpLogin(page: Page, credentials: SAMLCredentials): Promise<AuthenticationResult> {
    try {
      // Wait for IdP login form
      const loginFormExists = await this.waitForElement(page, this.getIdpLoginFormSelector(), 10000);
      if (!loginFormExists) {
        return {
          success: false,
          errorMessage: 'IdP login form not found',
        };
      }

      // Fill credentials
      await page.fill(this.getUsernameSelector(), credentials.username);
      await page.fill(this.getPasswordSelector(), credentials.password);

      // Submit form
      await page.click(this.getSubmitSelector());

      // Wait for form submission
      await page.waitForLoadState('networkidle');

      // Check for errors
      const errorElement = page.locator('[data-testid="saml-error"], .error-message').first();
      if (await errorElement.isVisible()) {
        const errorText = await errorElement.textContent();
        return {
          success: false,
          errorMessage: errorText || 'IdP login failed',
        };
      }

      return { success: true };
    } catch (error) {
      return {
        success: false,
        errorMessage: `IdP login failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  private async waitForSAMLResponse(page: Page): Promise<string | null> {
    try {
      // Wait for redirect to ACS URL
      await this.waitForUrl(page, new RegExp(this.config.spAcsUrl), 15000);

      // Extract SAML response from form or URL
      const samlResponse = await page.evaluate(() => {
        // Check for SAML response in form
        const responseInput = document.querySelector('input[name="SAMLResponse"]') as HTMLInputElement;
        if (responseInput) {
          return responseInput.value;
        }

        // Check URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get('SAMLResponse');
      });

      return samlResponse;
    } catch {
      return null;
    }
  }

  private processSAMLResponse(encodedResponse: string): {
    valid: boolean;
    error?: string;
    nameId?: string;
    assertions?: Record<string, any>;
  } {
    try {
      // Decode base64 response
      const decodedResponse = Buffer.from(encodedResponse, 'base64').toString('utf-8');

      // Simulate SAML response validation
      // In real scenario, you would:
      // 1. Parse XML
      // 2. Validate signature
      // 3. Check timestamps
      // 4. Verify issuer
      // 5. Extract assertions

      if (!decodedResponse.includes('samlp:Response')) {
        return { valid: false, error: 'Invalid SAML response format' };
      }

      // Simulate successful validation
      const nameId = this.extractNameIdFromResponse(decodedResponse);
      const assertions = this.extractAssertionsFromResponse(decodedResponse);

      return {
        valid: true,
        nameId,
        assertions,
      };
    } catch (err) {
      return {
        valid: false,
        error: `SAML response processing failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
      };
    }
  }

  private extractNameIdFromResponse(_response: string): string {
    // Simulate NameID extraction
    // In real scenario, parse XML properly
    return `user_${CryptoJS.lib.WordArray.random(8).toString()}@${this.provider}`;
  }

  private extractAssertionsFromResponse(_response: string): Record<string, any> {
    // Simulate attribute extraction from SAML assertions
    // In real scenario, parse XML and extract AttributeStatement

    const simulatedAttributes: Record<string, any> = {
      'urn:oid:2.5.4.3': 'Test User', // Common Name
      'urn:oid:0.9.2342.19200300.100.1.3': 'testuser@example.com', // Email
      'urn:oid:2.5.4.4': 'User', // Surname
      'urn:oid:2.5.4.42': 'Test', // Given Name
      'urn:oid:2.5.4.12': 'Engineering', // Department
      'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': ['user', 'developer'], // Roles
      'urn:oid:2.16.840.1.113730.3.1.241': 'Test User Display Name', // Display Name
    };

    return simulatedAttributes;
  }

  private extractUserDataFromSAML(assertions: Record<string, any>): UserData {
    const mapping = this.config.attributeMapping;

    // Map SAML attributes to user data using configured mapping
    const userData: UserData = {
      id: this.generateUserId(),
      email: this.getAttributeValue(assertions, mapping.email) || 'unknown@example.com',
      name: this.getAttributeValue(assertions, mapping.name) || 'Unknown User',
      role: this.mapSAMLRoleToApplicationRole(this.getAttributeValue(assertions, mapping.role)),
      permissions: [],
      provider: this.provider,
      providerId: this.getAttributeValue(assertions, mapping.id),
      verified: true,
      lastLogin: new Date(),
    };

    // Set permissions based on role
    userData.permissions = this.getPermissionsForRole(userData.role);

    return userData;
  }

  private getAttributeValue(assertions: Record<string, any>, attributeName?: string): string {
    if (!attributeName || !assertions[attributeName]) {
      return '';
    }

    const value = assertions[attributeName];
    return Array.isArray(value) ? value[0] : value;
  }

  private mapSAMLRoleToApplicationRole(samlRole: string): string {
    const roleMapping: Record<string, string> = {
      admin: 'admin',
      administrator: 'admin',
      manager: 'admin',
      user: 'customer',
      employee: 'customer',
      developer: 'customer',
      guest: 'guest',
    };

    return roleMapping[samlRole?.toLowerCase()] || 'customer';
  }

  private getPermissionsForRole(role: string): string[] {
    const permissions: Record<string, string[]> = {
      admin: ['saml:read', 'saml:write', 'admin:read', 'admin:write', 'users:read', 'users:write'],
      customer: ['profile:read', 'profile:write', 'saml:read'],
      guest: ['profile:read'],
    };
    return permissions[role] || permissions.guest;
  }

  // IdP-specific selectors
  private getIdpLoginFormSelector(): string {
    const selectors: Record<string, string> = {
      okta: '#signin-username',
      adfs: '#userNameInput',
      azuread: '[data-testid="i0116"]',
      ping: '#username',
      default: '[data-testid="username"], input[name="username"], #username',
    };
    return selectors[this.provider] || selectors.default;
  }

  private getUsernameSelector(): string {
    const selectors: Record<string, string> = {
      okta: '#signin-username',
      adfs: '#userNameInput',
      azuread: '[data-testid="i0116"]',
      ping: '#username',
      default: '[data-testid="username"], input[name="username"], #username',
    };
    return selectors[this.provider] || selectors.default;
  }

  private getPasswordSelector(): string {
    const selectors: Record<string, string> = {
      okta: '#signin-password',
      adfs: '#passwordInput',
      azuread: '[data-testid="i0118"]',
      ping: '#password',
      default: '[data-testid="password"], input[name="password"], #password',
    };
    return selectors[this.provider] || selectors.default;
  }

  private getSubmitSelector(): string {
    const selectors: Record<string, string> = {
      okta: '#signin-submit',
      adfs: '#submitButton',
      azuread: '[data-testid="idSIButton9"]',
      ping: '#signin-submit',
      default: '[data-testid="submit"], button[type="submit"], input[type="submit"]',
    };
    return selectors[this.provider] || selectors.default;
  }

  private generateRelayState(): string {
    return CryptoJS.lib.WordArray.random(16).toString();
  }

  private generateUserId(): string {
    return `saml_${this.provider}_${CryptoJS.lib.WordArray.random(8).toString()}`;
  }

  private generateJWTToken(userData: UserData): string {
    const payload = {
      sub: userData.id,
      email: userData.email,
      name: userData.name,
      role: userData.role,
      permissions: userData.permissions,
      authType: 'saml',
      provider: this.provider,
      providerId: userData.providerId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.authConfig.sessionTimeout,
      aud: this.authConfig.testDomain,
      iss: 'testwrightx-auth',
    };

    return jwt.sign(payload, this.authConfig.jwtSecret, { algorithm: 'HS256' });
  }

  public async logout(page: Page, context: BrowserContext): Promise<void> {
    // Initiate SAML logout if supported
    const logoutUrl = `${this.config.idpUrl}/logout`;

    try {
      await page.goto(logoutUrl);
      await page.waitForLoadState('networkidle');
    } catch {
      // Continue with local logout if IdP logout fails
    }

    // Clear local session
    await super.logout!(page, context);

    logger.audit('SAML logout completed', undefined, { provider: this.provider }, this.sessionId);
  }

  public getConfig(): Record<string, any> {
    return {
      name: this.name,
      type: this.type,
      provider: this.provider,
      idpUrl: this.config.idpUrl,
      spEntityId: this.config.spEntityId,
      nameIdFormat: this.config.nameIdFormat,
      attributeMapping: this.config.attributeMapping,
      supportedProviders: ['okta', 'adfs', 'azuread', 'ping', 'generic'],
    };
  }
}
