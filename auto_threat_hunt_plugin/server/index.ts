import { PluginInitializerContext } from '../../../core/server';
import { AutoThreatHuntPlugin } from './plugin';

// This exports static code and TypeScript types,
// as well as, OpenSearch Dashboards Platform `plugin()` initializer.

export function plugin(initializerContext: PluginInitializerContext) {
  return new AutoThreatHuntPlugin(initializerContext);
}

export { AutoThreatHuntPluginSetup, AutoThreatHuntPluginStart } from './types';
