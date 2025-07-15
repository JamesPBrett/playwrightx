import { IAuthenticationStrategy } from '@auth/strategies/base/AuthenticationStrategy';
import { OAuth2Strategy, OAuth2ProviderConfig } from '@auth/strategies/OAuth2Strategy';
import { ApiKeyStrategy } from '@auth/strategies/ApiKeyStrategy';
import { SAMLStrategy, SAMLConfig } from '@auth/strategies/SAMLStrategy';
import { SecurePasswordStrategy } from '@auth/strategies/SecurePasswordStrategy';
import { AuthConfigManager } from '@auth/config/AuthConfig';
import { logger } from '@auth/utils/SecureLogger';

export interface StrategyConfig {
  type: 'password' | 'oauth' | 'saml' | 'apikey' | 'jwt' | 'social' | 'sso' | 'mfa';
  provider?: string;
  config?: any;
}

export interface OAuth2ProviderPreset {
  name: string;
  authUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scope: string[];
}

/**
 * Factory for creating and configuring authentication strategies
 */
export class AuthenticationStrategyFactory {
  private static instance: AuthenticationStrategyFactory;
  private authConfig = AuthConfigManager.getInstance().getConfig();

  // Predefined OAuth2 provider configurations
  private oauth2Presets: Record<string, OAuth2ProviderPreset> = {
    google: {
      name: 'Google',
      authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
      scope: ['openid', 'email', 'profile'],
    },
    facebook: {
      name: 'Facebook',
      authUrl: 'https://www.facebook.com/v18.0/dialog/oauth',
      tokenUrl: 'https://graph.facebook.com/v18.0/oauth/access_token',
      userInfoUrl: 'https://graph.facebook.com/v18.0/me',
      scope: ['email', 'public_profile'],
    },
    github: {
      name: 'GitHub',
      authUrl: 'https://github.com/login/oauth/authorize',
      tokenUrl: 'https://github.com/login/oauth/access_token',
      userInfoUrl: 'https://api.github.com/user',
      scope: ['user:email', 'read:user'],
    },
    microsoft: {
      name: 'Microsoft',
      authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
      scope: ['openid', 'email', 'profile'],
    },
    linkedin: {
      name: 'LinkedIn',
      authUrl: 'https://www.linkedin.com/oauth/v2/authorization',
      tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken',
      userInfoUrl: 'https://api.linkedin.com/v2/people/~',
      scope: ['r_liteprofile', 'r_emailaddress'],
    },
  };

  // Predefined SAML provider configurations
  private samlPresets: Record<string, Partial<SAMLConfig>> = {
    okta: {
      nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      attributeMapping: {
        email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        role: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
        id: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
      },
    },
    adfs: {
      nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      attributeMapping: {
        email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        role: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
        id: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
      },
    },
    azuread: {
      nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      attributeMapping: {
        email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname',
        role: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
        id: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/objectidentifier',
      },
    },
  };

  private constructor() {}

  public static getInstance(): AuthenticationStrategyFactory {
    if (!AuthenticationStrategyFactory.instance) {
      AuthenticationStrategyFactory.instance = new AuthenticationStrategyFactory();
    }
    return AuthenticationStrategyFactory.instance;
  }

  /**
   * Create an authentication strategy based on configuration
   */
  public create(config: StrategyConfig): IAuthenticationStrategy {
    logger.info('Creating authentication strategy', {
      type: config.type,
      provider: config.provider,
    });

    switch (config.type) {
      case 'password':
        return this.createPasswordStrategy();

      case 'oauth':
        return this.createOAuth2Strategy(config.provider!, config.config);

      case 'saml':
        return this.createSAMLStrategy(config.provider!, config.config);

      case 'apikey':
        return this.createApiKeyStrategy();

      default:
        throw new Error(`Unsupported authentication strategy type: ${config.type}`);
    }
  }

  /**
   * Create a secure password strategy
   */
  public createPasswordStrategy(): IAuthenticationStrategy {
    return new SecurePasswordStrategy();
  }

  /**
   * Create an OAuth2 strategy for a specific provider
   */
  public createOAuth2Strategy(provider: string, customConfig?: Partial<OAuth2ProviderConfig>): IAuthenticationStrategy {
    const preset = this.oauth2Presets[provider.toLowerCase()];
    if (!preset) {
      throw new Error(`Unsupported OAuth2 provider: ${provider}`);
    }

    const config: OAuth2ProviderConfig = {
      name: preset.name,
      authUrl: preset.authUrl,
      tokenUrl: preset.tokenUrl,
      userInfoUrl: preset.userInfoUrl,
      clientId: process.env[`${provider.toUpperCase()}_CLIENT_ID`] || 'test-client-id',
      clientSecret: process.env[`${provider.toUpperCase()}_CLIENT_SECRET`] || 'test-client-secret',
      scope: preset.scope,
      redirectUri: `${this.authConfig.baseUrl}/auth/callback/${provider}`,
      responseType: 'code',
      grantType: 'authorization_code',
      ...customConfig,
    };

    return new OAuth2Strategy(provider, config);
  }

  /**
   * Create a SAML strategy for a specific provider
   */
  public createSAMLStrategy(provider: string, customConfig?: Partial<SAMLConfig>): IAuthenticationStrategy {
    const preset = this.samlPresets[provider.toLowerCase()];
    if (!preset) {
      throw new Error(`Unsupported SAML provider: ${provider}. Supported: ${Object.keys(this.samlPresets).join(', ')}`);
    }

    const config: SAMLConfig = {
      idpUrl: process.env[`${provider.toUpperCase()}_IDP_URL`] || `https://${provider}.example.com/saml/login`,
      spEntityId: process.env.SAML_SP_ENTITY_ID || `https://${this.authConfig.testDomain}/saml/metadata`,
      spAcsUrl: `${this.authConfig.baseUrl}/auth/saml/acs`,
      nameIdFormat: preset.nameIdFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      attributeMapping: preset.attributeMapping || {
        email: 'email',
        name: 'name',
        role: 'role',
        id: 'id',
      },
      ...customConfig,
    };

    return new SAMLStrategy(provider, config);
  }

  /**
   * Create an API key strategy
   */
  public createApiKeyStrategy(): IAuthenticationStrategy {
    return new ApiKeyStrategy();
  }

  /**
   * Create multiple strategies from configuration
   */
  public createMultiple(configs: StrategyConfig[]): IAuthenticationStrategy[] {
    return configs.map(config => this.create(config));
  }

  /**
   * Create a pre-configured set of common strategies
   */
  public createCommonStrategies(): IAuthenticationStrategy[] {
    const strategies: IAuthenticationStrategy[] = [];

    // Always include password strategy
    strategies.push(this.createPasswordStrategy());

    // Add API key strategy
    strategies.push(this.createApiKeyStrategy());

    // Add OAuth2 strategies if environment variables are set
    const oauth2Providers = ['google', 'facebook', 'github', 'microsoft'];
    for (const provider of oauth2Providers) {
      const clientIdEnv = `${provider.toUpperCase()}_CLIENT_ID`;
      if (process.env[clientIdEnv]) {
        try {
          strategies.push(this.createOAuth2Strategy(provider));
          logger.info(`Added OAuth2 strategy for ${provider}`);
        } catch (error) {
          logger.warn(`Failed to create OAuth2 strategy for ${provider}`, {
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }
    }

    // Add SAML strategies if environment variables are set
    const samlProviders = ['okta', 'adfs', 'azuread'];
    for (const provider of samlProviders) {
      const idpUrlEnv = `${provider.toUpperCase()}_IDP_URL`;
      if (process.env[idpUrlEnv]) {
        try {
          strategies.push(this.createSAMLStrategy(provider));
          logger.info(`Added SAML strategy for ${provider}`);
        } catch (error) {
          logger.warn(`Failed to create SAML strategy for ${provider}`, {
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }
    }

    return strategies;
  }

  /**
   * Get available OAuth2 providers
   */
  public getAvailableOAuth2Providers(): string[] {
    return Object.keys(this.oauth2Presets);
  }

  /**
   * Get available SAML providers
   */
  public getAvailableSAMLProviders(): string[] {
    return Object.keys(this.samlPresets);
  }

  /**
   * Add custom OAuth2 provider preset
   */
  public addOAuth2Preset(name: string, config: OAuth2ProviderPreset): void {
    this.oauth2Presets[name.toLowerCase()] = config;
    logger.info(`Added custom OAuth2 preset: ${name}`);
  }

  /**
   * Add custom SAML provider preset
   */
  public addSAMLPreset(name: string, config: Partial<SAMLConfig>): void {
    this.samlPresets[name.toLowerCase()] = config;
    logger.info(`Added custom SAML preset: ${name}`);
  }

  /**
   * Get configuration template for a strategy type
   */
  public getConfigTemplate(type: string, provider?: string): Record<string, any> {
    switch (type) {
      case 'oauth':
        if (provider && this.oauth2Presets[provider]) {
          return {
            clientId: `${provider.toUpperCase()}_CLIENT_ID (environment variable)`,
            clientSecret: `${provider.toUpperCase()}_CLIENT_SECRET (environment variable)`,
            redirectUri: `${this.authConfig.baseUrl}/auth/callback/${provider}`,
            scope: this.oauth2Presets[provider].scope,
          };
        }
        return { error: 'Provider not found or not specified' };

      case 'saml':
        if (provider && this.samlPresets[provider]) {
          return {
            idpUrl: `${provider.toUpperCase()}_IDP_URL (environment variable)`,
            spEntityId: 'SAML_SP_ENTITY_ID (environment variable)',
            spAcsUrl: `${this.authConfig.baseUrl}/auth/saml/acs`,
            attributeMapping: this.samlPresets[provider].attributeMapping,
          };
        }
        return { error: 'Provider not found or not specified' };

      case 'apikey':
        return {
          apiKey: 'Your API key',
          apiSecret: 'Your API secret (optional, for HMAC)',
          algorithm: 'HMAC-SHA256 | RSA-SHA256 | simple',
          customHeaders: 'Custom headers object (optional)',
        };

      case 'password':
        return {
          email: 'user@example.com',
          password: 'userpassword',
        };

      default:
        return { error: 'Unknown strategy type' };
    }
  }

  /**
   * Validate strategy configuration
   */
  public validateConfig(config: StrategyConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.type) {
      errors.push('Strategy type is required');
    }

    if (['oauth', 'saml'].includes(config.type) && !config.provider) {
      errors.push('Provider is required for OAuth and SAML strategies');
    }

    if (config.type === 'oauth' && config.provider && !this.oauth2Presets[config.provider]) {
      errors.push(`Unsupported OAuth2 provider: ${config.provider}`);
    }

    if (config.type === 'saml' && config.provider && !this.samlPresets[config.provider]) {
      errors.push(`Unsupported SAML provider: ${config.provider}`);
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}
