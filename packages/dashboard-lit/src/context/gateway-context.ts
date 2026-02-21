import { createContext } from "@lit/context";
import type {
  GatewayClientEventFrame,
  GatewayClientHelloOk,
} from "@openclaw/dashboard-gateway-client";

export type GatewayState = {
  connected: boolean;
  connecting: boolean;
  lastError: string | null;
  hello: GatewayClientHelloOk | null;
  lastEvent: GatewayClientEventFrame | null;
  gatewayUrl: string;
  request: <T = unknown>(method: string, params?: unknown) => Promise<T>;
  reconnect: (settings: { gatewayUrl: string; sharedSecret: string }) => void;
};

export const gatewayContext = createContext<GatewayState>("dashboard-gateway");
