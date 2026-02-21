import type { ActiveCheck } from '../scanner/active/index.js';

/** Metadata for a secbot plugin */
export interface PluginMeta {
  name: string;
  version?: string;
  description?: string;
  author?: string;
}

/**
 * A SecBot plugin — an ActiveCheck with optional metadata.
 *
 * Plugin files should default-export an object conforming to this interface:
 *
 * ```js
 * export default {
 *   name: 'my-custom-check',
 *   description: 'Custom security check',
 *   run: async (context, targets, config) => { ... }
 * }
 * ```
 */
export interface SecbotPlugin extends ActiveCheck {
  /** Optional plugin metadata */
  meta?: PluginMeta;
}
