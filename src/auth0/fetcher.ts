export type Fetcher = (
  input: string | URL,
  init?: RequestInit,
) => Promise<Response>;
