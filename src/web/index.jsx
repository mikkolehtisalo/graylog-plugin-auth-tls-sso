import packageJson from '../../package.json';
import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';
import SsoConfiguration from "./SsoConfiguration";

PluginStore.register(new PluginManifest(packageJson, {
  authenticatorConfigurations: [
    {
      name: 'sso',
      displayName: 'Single Sign-On (TLS SSO)',
      description: 'Creates and authenticates users based on HTTP certificate header',
      canBeDisabled: true,
      component: SsoConfiguration,
    },
  ]
}));
