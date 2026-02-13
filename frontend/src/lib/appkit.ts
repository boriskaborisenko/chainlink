import { WagmiAdapter } from "@reown/appkit-adapter-wagmi";
import { AppKitProvider, type CreateAppKit } from "@reown/appkit/react";
import { mainnet, sepolia } from "@reown/appkit/networks";
import type { AppKitNetwork } from "@reown/appkit-common";
import { defineChain, http } from "viem";
import { env } from "./env";

function buildActiveNetwork(): AppKitNetwork {
  if (env.chainId === 1) {
    return mainnet;
  }

  if (env.chainId === 11155111) {
    return sepolia;
  }

  const chainId = env.chainId > 0 ? env.chainId : 31337;
  const rpcUrl = env.rpcUrl ?? "http://127.0.0.1:8545";

  return defineChain({
    id: chainId,
    name: chainId === 31337 ? "Localhost Hardhat" : `EVM ${chainId}`,
    network: chainId === 31337 ? "localhost" : `evm-${chainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: {
      default: { http: [rpcUrl] },
      public: { http: [rpcUrl] }
    },
    blockExplorers: {
      default: { name: "Explorer", url: rpcUrl }
    },
    testnet: true
  });
}

const activeNetwork = buildActiveNetwork();
const appKitNetworks = [activeNetwork] as [AppKitNetwork, ...AppKitNetwork[]];
const activeChainId = Number(activeNetwork.id);
const activeRpcUrl = env.rpcUrl ?? activeNetwork.rpcUrls.default.http[0] ?? "http://127.0.0.1:8545";

const wagmiAdapter = new WagmiAdapter({
  projectId: env.walletConnectProjectId,
  networks: appKitNetworks,
  ssr: false,
  transports: {
    [activeChainId]: http(activeRpcUrl)
  }
});

const metadata = {
  name: "PassStore",
  description: "PassStore + Sumsub no-backend demo",
  url: globalThis.location?.origin ?? "http://localhost:5173",
  icons: [`${globalThis.location?.origin ?? "http://localhost:5173"}/favicon.ico`]
};

export const appKitConfig: CreateAppKit = {
  projectId: env.walletConnectProjectId,
  metadata,
  adapters: [wagmiAdapter],
  networks: appKitNetworks,
  defaultNetwork: activeNetwork,
  themeMode: "light"
};

export { AppKitProvider };
