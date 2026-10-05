// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Passkeys (WebAuthn): o servidor manda as opções em JSON (binários em
// base64url) e recebe a resposta do navegador no mesmo formato.

type Json = Record<string, unknown>

const fromB64u = (s: string): ArrayBuffer => {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

const toB64u = (buf: ArrayBuffer | null | undefined): string | undefined => {
  if (!buf) return undefined
  let s = ''
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const withIds = (list: unknown) =>
  Array.isArray(list) ? list.map((c: Json) => ({ ...c, id: fromB64u(c.id as string) })) : undefined

/** Passkeys só funcionam com HTTPS (ou localhost) e por um nome, não por IP. */
export function passkeySupport(): 'ok' | 'browser' | 'address' {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) return 'browser'
  const h = location.hostname
  const ip = /^[\d.]+$/.test(h) || h.includes(':') || h.startsWith('[')
  if (!window.isSecureContext || ip) return 'address'
  return 'ok'
}

export async function createPasskey(options: Json): Promise<Json> {
  const user = options.user as Json
  const publicKey = {
    ...options,
    challenge: fromB64u(options.challenge as string),
    user: { ...user, id: fromB64u(user.id as string) },
    excludeCredentials: withIds(options.excludeCredentials),
  } as unknown as PublicKeyCredentialCreationOptions
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null
  if (!cred) throw new Error('cancelado')
  const r = cred.response as AuthenticatorAttestationResponse
  return {
    id: cred.id,
    rawId: toB64u(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toB64u(r.clientDataJSON),
      attestationObject: toB64u(r.attestationObject),
      transports: r.getTransports?.() ?? [],
    },
  }
}

export async function getPasskey(options: Json): Promise<Json> {
  const publicKey = {
    ...options,
    challenge: fromB64u(options.challenge as string),
    allowCredentials: withIds(options.allowCredentials),
  } as unknown as PublicKeyCredentialRequestOptions
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null
  if (!cred) throw new Error('cancelado')
  const r = cred.response as AuthenticatorAssertionResponse
  return {
    id: cred.id,
    rawId: toB64u(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toB64u(r.clientDataJSON),
      authenticatorData: toB64u(r.authenticatorData),
      signature: toB64u(r.signature),
      userHandle: toB64u(r.userHandle),
    },
  }
}

/** Desafio vindo do servidor: { challenge_id, options }. */
export type PasskeyChallenge = { challenge_id: string; options: Json }

/** Responde um desafio de login e devolve o corpo para o servidor. */
export async function answer(ch: PasskeyChallenge) {
  return { challenge_id: ch.challenge_id, credential: await getPasskey(ch.options) }
}
