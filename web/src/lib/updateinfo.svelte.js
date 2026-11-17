import { api } from './api.js';

// Shared state of the "update available" badge in the header.
export const updateInfo = $state({ status: null });

export async function loadUpdateInfo() {
  try {
    updateInfo.status = await api.update();
  } catch {
    // an old controller without the endpoint, or a network blip: no badge
  }
}
