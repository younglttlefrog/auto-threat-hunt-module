import './index.scss';

import { AutoThreatHuntPlugin } from './plugin';

// This exports static code and TypeScript types,
// as well as, OpenSearch Dashboards Platform `plugin()` initializer.
export function plugin() {
  return new AutoThreatHuntPlugin();
}
export { AutoThreatHuntPluginSetup, AutoThreatHuntPluginStart } from './types';
