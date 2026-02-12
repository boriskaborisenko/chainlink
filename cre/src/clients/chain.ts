import { Contract, JsonRpcProvider, Wallet } from "ethers";
import { BROKER_ABI, REGISTRY_ABI } from "../abi.js";
import { config } from "../config.js";

const provider = new JsonRpcProvider(config.rpcUrl);
const wallet = new Wallet(config.creSignerPk, provider);

export function getProvider() {
  return provider;
}

export function getSigner() {
  return wallet;
}

export function getBroker() {
  return new Contract(config.brokerAddress, BROKER_ABI, wallet);
}

export function getRegistry() {
  return new Contract(config.registryAddress, REGISTRY_ABI, wallet);
}
