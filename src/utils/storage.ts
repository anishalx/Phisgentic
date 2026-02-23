// Chrome storage wrapper utilities

import type {
  StorageData,
  Settings,
  AnalysisHistoryEntry,
  FinalVerdict,
} from "../types";
import { DEFAULT_SETTINGS } from "../config";

const STORAGE_KEYS = {
  API_KEY: "apiKey",
  SETTINGS: "settings",
  HISTORY: "analysisHistory",
  WHITELIST: "whitelist",
} as const;

export async function getSettings(): Promise<Settings> {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
    return result[STORAGE_KEYS.SETTINGS] || DEFAULT_SETTINGS;
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export async function saveSettings(settings: Settings): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: settings });
}

export async function getApiKey(): Promise<string | null> {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.API_KEY);
    return result[STORAGE_KEYS.API_KEY] || null;
  } catch {
    return null;
  }
}

export async function saveApiKey(apiKey: string): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEYS.API_KEY]: apiKey });
}

export async function getWhitelist(): Promise<string[]> {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.WHITELIST);
    return result[STORAGE_KEYS.WHITELIST] || [];
  } catch {
    return [];
  }
}

export async function addToWhitelist(domain: string): Promise<void> {
  const whitelist = await getWhitelist();
  if (!whitelist.includes(domain)) {
    whitelist.push(domain);
    await chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: whitelist });
  }
}

export async function removeFromWhitelist(domain: string): Promise<void> {
  const whitelist = await getWhitelist();
  const filtered = whitelist.filter((d) => d !== domain);
  await chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: filtered });
}

export async function isWhitelisted(domain: string): Promise<boolean> {
  const whitelist = await getWhitelist();
  // Exact match or proper subdomain match (e.g., "mail.google.com" matches "google.com")
  return whitelist.some((d) => domain === d || domain.endsWith(`.${d}`));
}

export async function getAnalysisHistory(
  limit = 100,
): Promise<AnalysisHistoryEntry[]> {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.HISTORY);
    const history = result[STORAGE_KEYS.HISTORY] || [];
    return history.slice(-limit);
  } catch {
    return [];
  }
}

export async function addToHistory(
  url: string,
  verdict: FinalVerdict,
  userAction?: "proceeded" | "blocked",
): Promise<void> {
  const history = await getAnalysisHistory(99); // Keep last 99 to add new one
  history.push({
    url,
    verdict,
    timestamp: Date.now(),
    userAction,
  });
  await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: history });
}

export async function clearHistory(): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: [] });
}

export async function getAllData(): Promise<Partial<StorageData>> {
  return chrome.storage.local.get(null);
}
