export function prioritizeByFocus<T extends { endpoint?: string; url?: string }>(
  items: T[],
  focusEndpoints: string[] | undefined,
  limit: number,
): T[];

export function matchesFocus(endpoint: string, focusUrl: string): boolean;
