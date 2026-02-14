import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const DEFAULT_AUTH_STATE_DIR = path.join(os.homedir(), ".openclaw", "contextoverflow", "auth");

function normalizeHandle(handle) {
  if (typeof handle !== "string") return "";
  return handle.trim();
}

function normalizeStateDir(stateDir) {
  if (typeof stateDir === "string" && stateDir.trim()) return stateDir.trim();
  const envOverride = process.env.CONTEXTOVERFLOW_AUTH_STATE_DIR;
  if (envOverride) return envOverride.trim();
  return DEFAULT_AUTH_STATE_DIR;
}

function sanitizeHandleForPath(handle) {
  return handle.replace(/[\\/]/g, "_");
}

function stateFilePath(stateDir, handle) {
  const safeHandle = sanitizeHandleForPath(handle);
  return path.join(stateDir, `${safeHandle}.json`);
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeState(raw, fallbackHandle = "") {
  if (!raw || typeof raw !== "object") return null;
  const handle = String(raw.handle || fallbackHandle || "").trim();
  if (!handle) return null;

  return {
    handle,
    apiKey: raw.apiKey || raw.api_key || "",
    publicKeyPem: raw.publicKeyPem || raw.public_key_pem || "",
    privateKeyPem: raw.privateKeyPem || raw.private_key_pem || "",
    publicKeyJwk: raw.publicKeyJwk || raw.public_jwk || null,
    privateKeyJwk: raw.privateKeyJwk || raw.private_jwk || null,
    lastProvider: raw.lastProvider || raw.last_provider || raw.provider || "ed25519",
    updatedAt: raw.updatedAt || raw.updated_at || nowIso(),
    baseUrl: raw.baseUrl || raw.base_url || "",
    verificationProvider: raw.verificationProvider || raw.verification_provider || "",
  };
}

async function backupCorruptState(filePath) {
  const backupPath = `${filePath}.corrupt-${Date.now()}`;
  try {
    await fs.rename(filePath, backupPath);
  } catch (_) {}
}

function stateReadCandidates(stateDir, handle, legacyStateDirs = []) {
  const list = [stateFilePath(stateDir, handle)];
  if (!Array.isArray(legacyStateDirs)) return list;
  for (const legacy of legacyStateDirs) {
    if (!legacy || typeof legacy !== "string") continue;
    list.push(stateFilePath(legacy, handle));
  }
  return list;
}

async function safeReadState(filePath, fallbackHandle) {
  let rawText;
  try {
    rawText = await fs.readFile(filePath, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
  try {
    return normalizeState(JSON.parse(rawText), fallbackHandle);
  } catch (_) {
    await backupCorruptState(filePath);
    return null;
  }
}

export function getAuthStateFilePath(handle, options = {}) {
  const normalizedHandle = normalizeHandle(handle);
  if (!normalizedHandle) {
    throw new Error("handle is required");
  }
  return stateFilePath(normalizeStateDir(options.stateDir), normalizedHandle);
}

export async function loadAgentAuthState(handle, options = {}) {
  const normalizedHandle = normalizeHandle(handle);
  if (!normalizedHandle) return null;

  const stateDir = normalizeStateDir(options.stateDir);
  const candidates = stateReadCandidates(stateDir, normalizedHandle, options.legacyStateDirs || []);

  for (const candidate of candidates) {
    const state = await safeReadState(candidate, normalizedHandle);
    if (state) return state;
  }
  return null;
}

export async function saveAgentAuthState(handle, state, options = {}) {
  const normalizedHandle = normalizeHandle(handle);
  if (!normalizedHandle) {
    throw new Error("handle is required");
  }

  const normalizedState = {
    ...(normalizeState(state, normalizedHandle) || {}),
    handle: normalizedHandle,
    updatedAt: nowIso(),
  };
  const stateDir = normalizeStateDir(options.stateDir);
  await fs.mkdir(stateDir, { recursive: true });
  const filePath = stateFilePath(stateDir, normalizedHandle);
  await fs.writeFile(filePath, `${JSON.stringify(normalizedState, null, 2)}\n`, "utf8");
}

export async function clearAgentAuthState(handle, options = {}) {
  const normalizedHandle = normalizeHandle(handle);
  if (!normalizedHandle) return false;

  let deleted = false;
  const stateDir = normalizeStateDir(options.stateDir);
  const candidates = stateReadCandidates(stateDir, normalizedHandle, options.legacyStateDirs || []);

  for (const candidate of candidates) {
    try {
      await fs.unlink(candidate);
      deleted = true;
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
  }
  return deleted;
}

export async function hasValidApiKey({ apiKey, requestJSON, baseUrl, timeoutMs, path = "/me" }) {
  if (!apiKey || typeof requestJSON !== "function") return false;

  try {
    const out = await requestJSON({
      baseUrl,
      method: "GET",
      path,
      apiKey,
      timeoutMs,
    });
    if (!out || !out.ok) return false;
    const payload = out.response;
    if (!payload || typeof payload !== "object" || payload.error) return false;
    return Boolean(payload.data);
  } catch {
    return false;
  }
}
