import { UserPersona } from '@auth/personas/UserPersona';
import { AdminPersona } from '@auth/personas/personas/AdminPersona';
import { CustomerPersona } from '@auth/personas/personas/CustomerPersona';
import { GuestPersona } from '@auth/personas/personas/GuestPersona';

/**
 * PersonaManager
 *
 * This manages all the different types of users in your system
 * and makes it easy to switch between them in tests.
 */
export class PersonaManager {
  // Storage for all persona types
  private personas: Map<string, UserPersona> = new Map();

  constructor() {
    // Set up the default personas that come with the framework
    this.initializeDefaultPersonas();
  }

  /**
   * Set up the basic user types (admin, customer, guest)
   */
  private initializeDefaultPersonas(): void {
    // Register each persona type with a unique identifier
    this.registerPersona('admin', new AdminPersona());
    this.registerPersona('customer', new CustomerPersona());
    this.registerPersona('guest', new GuestPersona());

    console.log('Default personas loaded: admin, customer, guest');
  }

  /**
   * Add a new user type to the system
   *
   * Example: Add a "manager" persona
   * personaManager.registerPersona('manager', new ManagerPersona());
   */
  registerPersona(type: string, persona: UserPersona): void {
    this.personas.set(type.toLowerCase(), persona);
    console.log(`Registered new persona: ${type}`);
  }

  /**
   * Get a specific user type
   *
   * Example: Get admin persona
   * const admin = personaManager.getPersona('admin');
   */
  getPersona(type: string): UserPersona | null {
    const persona = this.personas.get(type.toLowerCase());

    if (!persona) {
      const availableTypes = this.getAvailablePersonaTypes().join(', ');
      console.warn(`Persona '${type}' not found. Available: ${availableTypes}`);
      return null;
    }

    return persona;
  }

  /**
   * Get list of all available user types
   */
  getAvailablePersonaTypes(): string[] {
    return Array.from(this.personas.keys());
  }

  /**
   * Check if a user type exists
   */
  hasPersona(type: string): boolean {
    return this.personas.has(type.toLowerCase());
  }

  /**
   * Get summary of all personas and their capabilities
   */
  getPersonaSummary(): Record<string, any> {
    const summary: Record<string, any> = {};

    for (const [type, persona] of this.personas) {
      summary[type] = {
        name: persona.getName(),
        capabilities: persona.getCapabilities(),
        landingPage: persona.getExpectedLandingPage(),
        navigation: persona.getExpectedNavigationItems(),
      };
    }

    return summary;
  }
}
