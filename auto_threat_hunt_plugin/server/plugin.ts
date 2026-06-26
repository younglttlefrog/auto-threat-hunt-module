import {
  PluginInitializerContext,
  CoreSetup,
  CoreStart,
  Plugin,
  Logger,
} from '../../../core/server';

import { AutoThreatHuntPluginSetup, AutoThreatHuntPluginStart } from './types';
import { defineRoutes } from './routes';

export class AutoThreatHuntPlugin
  implements Plugin<AutoThreatHuntPluginSetup, AutoThreatHuntPluginStart> {
  private readonly logger: Logger;

  constructor(initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
  }

  public setup(core: CoreSetup) {
    this.logger.debug('autoThreatHunt: Setup');
    const router = core.http.createRouter();

    // Register server side APIs
    defineRoutes(router);

    return {};
  }

  public start(core: CoreStart) {
    this.logger.debug('autoThreatHunt: Started');
    return {};
  }

  public stop() {}
}
