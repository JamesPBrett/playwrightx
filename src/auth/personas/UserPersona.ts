// What can this user do?
export interface PersonaCapabilities {
  canViewAdminPanel: boolean;
  canManageUsers: boolean;
  canAccessReports: boolean;
  canModifySettings: boolean;
  canDeleteData: boolean;
  maxFileUploadSize: number;
  allowedFeatures: string[];
}

// Login information for this user type
export interface PersonaCredentials {
  email: string;
  password: string;
  apiKey?: string;
  role?: string;
}

// The "base character class" that all user types extend from
export abstract class UserPersona {
  protected name: string;
  protected capabilities: PersonaCapabilities;
  protected credentials: PersonaCredentials;
  protected testData: any;
  constructor(name: string, capabilities: PersonaCapabilities, credentials: PersonaCredentials, testData: any = {}) {
    this.name = name;
    this.capabilities = capabilities;
    this.credentials = credentials;
    this.testData = testData;
  }

  // Get the persona name
  getName(): string {
    return this.name;
  }

  // Get what this user can do
  getCapabilities(): PersonaCapabilities {
    return { ...this.capabilities }; // Return a copy to prevent changes
  }

  // Check if user has a specific ability
  hasCapability(capability: keyof PersonaCapabilities): boolean {
    return this.capabilities[capability] as boolean;
  }

  // Get login credentials
  getDefaultCredentials(): PersonaCredentials {
    return { ...this.credentials }; // Return a copy
  }

  // Get test data for this user
  getTestData(): any {
    return { ...this.testData };
  }

  // These methods must be implemented by each specific persona:
  // Where should user land after login?
  abstract getExpectedLandingPage(): string;

  // What menu items should they see?
  abstract getExpectedNavigationItems(): string[];

  // How do we verify they're properly logged in?
  abstract validateAuthentication(page: any): Promise<boolean>;
}
