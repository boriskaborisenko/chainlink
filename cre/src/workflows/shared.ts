export function shouldLoop(): boolean {
  return process.argv.includes("--loop");
}

export async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
