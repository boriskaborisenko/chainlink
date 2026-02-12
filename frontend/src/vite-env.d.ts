/// <reference types="vite/client" />

declare global {
  interface Window {
    ethereum?: {
      request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
      on?: (event: string, callback: (...args: any[]) => void) => void;
      removeListener?: (event: string, callback: (...args: any[]) => void) => void;
    };
    snsWebSdk?: {
      init: (token: string, tokenUpdate: () => Promise<string>) => {
        withConf: (conf: Record<string, unknown>) => any;
        withOptions: (options: Record<string, unknown>) => any;
        on: (event: string, cb: (...args: any[]) => void) => any;
        build: () => { launch: (selector: string) => void };
      };
    };
  }
}

export {};
