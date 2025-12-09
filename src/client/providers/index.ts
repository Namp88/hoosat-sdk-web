export { type ApiProvider, type ProviderConfig, type EndpointConfig } from './api-provider.interface';
export { BaseProvider } from './base-provider';
export { HoosatProxyProvider } from './hoosat-proxy-provider';
export { HoosatNetworkProvider } from './hoosat-network-provider';
export { MultiProvider, type MultiProviderConfig } from './multi-provider';

import type { ApiProvider, ProviderConfig } from './api-provider.interface';
import { HoosatProxyProvider } from './hoosat-proxy-provider';
import { HoosatNetworkProvider } from './hoosat-network-provider';
import { MultiProvider, type MultiProviderConfig } from './multi-provider';

export const createHoosatProxyProvider = (baseUrl: string, options?: Partial<ProviderConfig>) => {
  return new HoosatProxyProvider({
    baseUrl,
    ...options,
  });
};

export const createHoosatNetworkProvider = (baseUrl: string, options?: Partial<ProviderConfig>) => {
  return new HoosatNetworkProvider({
    baseUrl,
    ...options,
  });
};

export const createMultiProvider = (providers: ApiProvider[], strategy?: MultiProviderConfig['strategy']) => {
  return new MultiProvider({
    providers,
    strategy,
  });
};