import { AuthConfigManager } from '@auth/config/AuthConfig';

export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug';

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  metadata?: Record<string, any>;
  sessionId?: string;
}

/**
 * Secure logger that masks sensitive information and provides audit trails
 */
export class SecureLogger {
  private static instance: SecureLogger;
  private config = AuthConfigManager.getInstance().getConfig();
  private auditLog: LogEntry[] = [];

  // Patterns to identify and mask sensitive data
  private sensitivePatterns = [/password/i, /token/i, /secret/i, /key/i, /auth/i, /credential/i, /session/i];

  private constructor() {}

  public static getInstance(): SecureLogger {
    if (!SecureLogger.instance) {
      SecureLogger.instance = new SecureLogger();
    }
    return SecureLogger.instance;
  }

  private shouldLog(level: LogLevel): boolean {
    const levels: LogLevel[] = ['silent', 'error', 'warn', 'info', 'debug'];
    const configLevel = this.config.logging.level;

    if (configLevel === 'silent') {
      return false;
    }

    const configIndex = levels.indexOf(configLevel);
    const messageIndex = levels.indexOf(level);

    return messageIndex <= configIndex;
  }

  private maskSensitiveData(data: any): any {
    if (typeof data === 'string') {
      // Mask potential tokens, passwords, etc.
      return data.replace(/[a-zA-Z0-9+/]{20,}/g, '***MASKED***');
    }

    if (typeof data === 'object' && data !== null) {
      const masked = { ...data };

      for (const key in masked) {
        if (this.isSensitiveKey(key)) {
          masked[key] = '***MASKED***';
        } else if (typeof masked[key] === 'object') {
          masked[key] = this.maskSensitiveData(masked[key]);
        }
      }

      return masked;
    }

    return data;
  }

  private isSensitiveKey(key: string): boolean {
    return this.sensitivePatterns.some(pattern => pattern.test(key));
  }

  private createLogEntry(
    level: LogLevel,
    message: string,
    metadata?: Record<string, any>,
    sessionId?: string,
  ): LogEntry {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
    };

    if (metadata !== undefined) {
      entry.metadata = this.config.logging.sensitiveDataMasking ? this.maskSensitiveData(metadata) : metadata;
    }

    if (sessionId !== undefined) {
      entry.sessionId = sessionId;
    }

    return entry;
  }

  private writeLog(entry: LogEntry): void {
    if (!this.shouldLog(entry.level)) {
      return;
    }

    // Add to audit trail if enabled
    if (this.config.logging.auditTrail) {
      this.auditLog.push(entry);

      // Keep audit log size manageable (last 1000 entries)
      if (this.auditLog.length > 1000) {
        this.auditLog.shift();
      }
    }

    // Format log output
    const timestamp = entry.timestamp;
    const level = entry.level.toUpperCase().padEnd(5);
    const sessionInfo = entry.sessionId ? ` [${entry.sessionId}]` : '';
    const metadataStr = entry.metadata ? ` ${JSON.stringify(entry.metadata)}` : '';

    const logMessage = `${timestamp} ${level}${sessionInfo} ${entry.message}${metadataStr}`;

    // Output based on level
    switch (entry.level) {
      case 'error':
        console.error(logMessage);
        break;
      case 'warn':
        console.warn(logMessage);
        break;
      case 'debug':
        console.debug(logMessage);
        break;
      default:
        console.log(logMessage);
    }
  }

  public debug(message: string, metadata?: Record<string, any>, sessionId?: string): void {
    const entry = this.createLogEntry('debug', message, metadata, sessionId);
    this.writeLog(entry);
  }

  public info(message: string, metadata?: Record<string, any>, sessionId?: string): void {
    const entry = this.createLogEntry('info', message, metadata, sessionId);
    this.writeLog(entry);
  }

  public warn(message: string, metadata?: Record<string, any>, sessionId?: string): void {
    const entry = this.createLogEntry('warn', message, metadata, sessionId);
    this.writeLog(entry);
  }

  public error(message: string, metadata?: Record<string, any>, sessionId?: string): void {
    const entry = this.createLogEntry('error', message, metadata, sessionId);
    this.writeLog(entry);
  }

  public security(message: string, metadata?: Record<string, any>, sessionId?: string): void {
    // Security events are always logged regardless of log level
    const entry = this.createLogEntry('warn', `[SECURITY] ${message}`, metadata, sessionId);
    this.writeLog(entry);
  }

  public audit(action: string, persona?: string, metadata?: Record<string, any>, sessionId?: string): void {
    const auditMessage = `Auth action: ${action}${persona ? ` for persona: ${persona}` : ''}`;
    const entry = this.createLogEntry('info', auditMessage, metadata, sessionId);
    this.writeLog(entry);
  }

  public getAuditTrail(): LogEntry[] {
    return [...this.auditLog]; // Return copy to prevent mutations
  }

  public clearAuditTrail(): void {
    this.auditLog = [];
    this.info('Audit trail cleared');
  }

  public exportAuditTrail(): string {
    return JSON.stringify(this.auditLog, null, 2);
  }
}

// Export singleton instance
export const logger = SecureLogger.getInstance();
