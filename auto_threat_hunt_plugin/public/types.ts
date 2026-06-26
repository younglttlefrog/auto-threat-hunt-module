import { NavigationPublicPluginStart } from '../../navigation/public';

export interface AutoThreatHuntPluginSetup {
  getGreeting: () => string;
}
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface AutoThreatHuntPluginStart {}

export interface AppPluginStartDependencies {
  navigation: NavigationPublicPluginStart;
}
