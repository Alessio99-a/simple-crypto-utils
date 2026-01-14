import { randomUUID } from "crypto";

/**
 * Generates a cryptographically secure UUID (version 4).
 *
 * @returns A string representing the UUID (e.g., "3b241101-e2bb-4255-8caf-4136c566a962").
 *
 * @example
 * ```ts
 * import { generateUUID } from "./uuid";
 *
 * const id = generateUUID();
 * console.log(id); // e.g., "3b241101-e2bb-4255-8caf-4136c566a962"
 * ```
 */
export function generateUUID(): string {
  return randomUUID();
}
