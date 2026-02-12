import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";
import { HardhatUserConfig } from "hardhat/config";

dotenv.config();

const { RPC_URL = "", PRIVATE_KEY = "" } = process.env;

const networks: HardhatUserConfig["networks"] = {
  hardhat: {},
  localhost: {
    url: "http://127.0.0.1:8545"
  }
};

if (RPC_URL) {
  networks.sepolia = {
    url: RPC_URL,
    accounts: PRIVATE_KEY ? [PRIVATE_KEY] : []
  };
}

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  networks
};

export default config;
