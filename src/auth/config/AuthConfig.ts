import { z } from 'zod';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Validation schema for auth configuration
const AuthConfigSchema = z.object({
  // Environment settings
  environment: z.enum(['development', 'staging', 'production']).default('development'),

  // Domain configuration
  testDomain: z.string().default('localhost'),
  baseUrl: z.string().default('http://localhost:3000'),

  // Security settings
  jwtSecret: z.string().min(32, 'JWT secret must be at least 32 characters'),
  sessionEncryptionKey: z.string().min(32, 'Encryption key must be at least 32 characters'),
  cookieSecure: z.boolean().default(false), // Auto-set based on environment
  cookieHttpOnly: z.boolean().default(true),
  sessionTimeout: z.number().min(300).default(3600), // 1 hour default

  // Credentials (required environment variables)
  credentials: z.object({
    admin: z.object({
      email: z.string().email(),
      password: z.string().min(8),
      role: z.string().default('administrator'),
    }),
    customer: z.object({
      email: z.string().email(),
      password: z.string().min(8),
      role: z.string().default('customer'),
    }),
    guest: z.object({
      email: z.string().refine(val => val === '' || z.string().email().safeParse(val).success, {
        message: 'Email must be empty or a valid email address'
      }).default(''),
      password: z.string().default(''),
      role: z.string().default('guest'),
    }),
  }),

  // Rate limiting simulation
  rateLimiting: z.object({
    enabled: z.boolean().default(true),
    maxAttempts: z.number().min(1).default(5),
    windowMs: z
      .number()
      .min(1000)
      .default(15 * 60 * 1000), // 15 minutes
    blockDuration: z
      .number()
      .min(1000)
      .default(15 * 60 * 1000), // 15 minutes
  }),

  // CSRF protection
  csrf: z.object({
    enabled: z.boolean().default(true),
    tokenLength: z.number().min(16).default(32),
  }),

  // Logging configuration
  logging: z.object({
    level: z.enum(['silent', 'error', 'warn', 'info', 'debug']).default('info'),
    sensitiveDataMasking: z.boolean().default(true),
    auditTrail: z.boolean().default(true),
  }),
});

export type AuthConfig = z.infer<typeof AuthConfigSchema>;

class AuthConfigManager {
  private static instance: AuthConfigManager;
  private config: AuthConfig;

  private constructor() {
    this.config = this.loadConfig();
  }

  public static getInstance(): AuthConfigManager {
    if (!AuthConfigManager.instance) {
      AuthConfigManager.instance = new AuthConfigManager();
    }
    return AuthConfigManager.instance;
  }

  private loadConfig(): AuthConfig {
    const rawConfig = {
      // Environment
      environment: process.env.NODE_ENV || 'development',
      testDomain: process.env.TEST_DOMAIN || 'localhost',
      baseUrl: process.env.BASE_URL || 'http://localhost:3000',

      // Security
      jwtSecret: process.env.JWT_SECRET || this.generateSecureDefault('jwt'),
      sessionEncryptionKey: process.env.SESSION_ENCRYPTION_KEY || this.generateSecureDefault('session'),
      cookieSecure: process.env.NODE_ENV === 'production',
      cookieHttpOnly: process.env.COOKIE_HTTP_ONLY !== 'false',
      sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '3600', 10),

      // Credentials
      credentials: {
        admin: {
          email: process.env.ADMIN_EMAIL || this.getRequiredEnv('ADMIN_EMAIL'),
          password: process.env.ADMIN_PASSWORD || this.getRequiredEnv('ADMIN_PASSWORD'),
          role: 'administrator',
        },
        customer: {
          email: process.env.CUSTOMER_EMAIL || this.getRequiredEnv('CUSTOMER_EMAIL'),
          password: process.env.CUSTOMER_PASSWORD || this.getRequiredEnv('CUSTOMER_PASSWORD'),
          role: 'customer',
        },
        guest: {
          email: '',
          password: '',
          role: 'guest',
        },
      },

      // Rate limiting
      rateLimiting: {
        enabled: process.env.RATE_LIMITING_ENABLED !== 'false',
        maxAttempts: parseInt(process.env.RATE_LIMIT_MAX_ATTEMPTS || '5', 10),
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
        blockDuration: parseInt(process.env.RATE_LIMIT_BLOCK_DURATION || '900000', 10),
      },

      // CSRF
      csrf: {
        enabled: process.env.CSRF_ENABLED !== 'false',
        tokenLength: parseInt(process.env.CSRF_TOKEN_LENGTH || '32', 10),
      },

      // Logging
      logging: {
        level: (process.env.LOG_LEVEL as any) || 'info',
        sensitiveDataMasking: process.env.SENSITIVE_DATA_MASKING !== 'false',
        auditTrail: process.env.AUDIT_TRAIL !== 'false',
      },
    };

    try {
      return AuthConfigSchema.parse(rawConfig);
    } catch (error) {
      if (error instanceof z.ZodError) {
        const missingFields = error.issues.map((issue: z.ZodIssue) => issue.path.join('.')).join(', ');
        throw new Error(`Auth configuration validation failed. Missing or invalid fields: ${missingFields}`);
      }
      throw error;
    }
  }

  private getRequiredEnv(key: string): string {
    const value = process.env[key];
    if (!value) {
      throw new Error(
        `Required environment variable ${key} is not set. Please check your .env file or environment configuration.`,
      );
    }
    return value;
  }

  private generateSecureDefault(type: string): string {
    const crypto = require('crypto');
    const randomKey = crypto.randomBytes(32).toString('hex');

    if (process.env.NODE_ENV !== 'production') {
      console.warn(
        `⚠️  Using auto-generated ${type} secret. Set ${type.toUpperCase()}_SECRET in your environment for production.`,
      );
    }

    return randomKey;
  }

  public getConfig(): AuthConfig {
    return { ...this.config }; // Return a copy to prevent mutations
  }

  public updateConfig(updates: Partial<AuthConfig>): void {
    this.config = AuthConfigSchema.parse({ ...this.config, ...updates });
  }

  public isProduction(): boolean {
    return this.config.environment === 'production';
  }

  public isDevelopment(): boolean {
    return this.config.environment === 'development';
  }

  public validateCredentials(persona: string): boolean {
    const creds = this.config.credentials[persona as keyof typeof this.config.credentials];
    if (!creds) {
      return false;
    }

    if (persona === 'guest') {
      return true;
    } // Guest doesn't need credentials

    return !!(creds.email && creds.password);
  }
}

export default AuthConfigManager;
export { AuthConfigManager };
