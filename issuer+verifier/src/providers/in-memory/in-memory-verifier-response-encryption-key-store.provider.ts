import { calculateJwkThumbprint } from 'jose'
import { raise } from '../../errors'
import { generateHpkeKeyPair, isSupportedHpkeAlgorithm } from '../../jose-hpke'
import { Jwk } from '../../jwk.type'
import {
  decryptAuthorizationResponse,
  isSupportedResponseEncryptionAlgorithm,
} from '../../response-encryption'
import { ResponseEncryptionKeyEntry } from '../../response-encryption-key.types'
import { VerifierResponseEncryptionKeyStoreProvider } from '../provider.types'

/**
 * Holds the Verifier's Authorization Response encryption keys in memory
 * (OID4VP 1.1 Section 8.3).
 *
 * One key pair is kept per JWE `alg`, so a Verifier that publishes several
 * algorithms lets Wallets pick whichever they support. Every published key
 * carries `use: "enc"`, its `alg`, and a `kid` that the Wallet echoes in the
 * response header, all of which Section 8.3 relies on for key selection.
 */
export const inMemoryVerifierResponseEncryptionKeyStore =
  (): VerifierResponseEncryptionKeyStoreProvider => {
    const map = new Map<string, ResponseEncryptionKeyEntry[]>()

    const publicKeysOf = (verifier: string): Jwk[] =>
      (map.get(verifier) ?? []).map((entry) => entry.publicKey)

    return {
      kind: 'verifier-response-encryption-key-store-provider',
      name: 'in-memory-verifier-response-encryption-key-store-provider',
      single: true,

      async save(verifier, keyAlgs, keys) {
        const entries: ResponseEncryptionKeyEntry[] = []

        for (const keyAlg of keyAlgs) {
          const supplied = keys?.find((key) => key.declaredAlg === keyAlg)
          if (supplied) {
            entries.push(supplied)
            continue
          }
          if (!isSupportedHpkeAlgorithm(keyAlg)) {
            // Only the JOSE HPKE algorithms can be generated here. A Verifier
            // wanting an ECDH-ES key supplies the pair it already holds.
            throw raise('invalid_options', {
              message: `Cannot generate a response encryption key for alg ${keyAlg}. Supply the key pair instead.`,
            })
          }

          const { publicKey, privateKey } = generateHpkeKeyPair(keyAlg)
          const kid = await calculateJwkThumbprint(
            publicKey as Parameters<typeof calculateJwkThumbprint>[0]
          )
          entries.push({
            declaredAlg: keyAlg,
            publicKey: { ...publicKey, kid },
            privateKey: { ...privateKey, kid },
          })
        }

        for (const entry of keys ?? []) {
          if (!isSupportedResponseEncryptionAlgorithm(entry.declaredAlg)) {
            throw raise('invalid_options', {
              message: `Unsupported response encryption alg ${entry.declaredAlg}.`,
            })
          }
          if (!keyAlgs.includes(entry.declaredAlg)) {
            entries.push(entry)
          }
        }

        map.set(verifier, entries)
        return publicKeysOf(verifier)
      },

      async fetch(verifier) {
        return publicKeysOf(verifier)
      },

      async decrypt(verifier, response, session) {
        const entries = map.get(verifier) ?? []
        if (entries.length === 0) {
          throw raise('authz_verifier_key_not_found', {
            message: `Verifier ${verifier} holds no response encryption key.`,
          })
        }
        return decryptAuthorizationResponse(
          response,
          entries.map((entry) => entry.privateKey),
          session
        )
      },
    }
  }
