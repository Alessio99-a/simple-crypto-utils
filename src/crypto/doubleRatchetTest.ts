import * as crypto from "crypto";
import type { KeyObject } from "crypto";

/**
 * STEP 1: Identity Key (firma, Ed25519)
 */
function generateIdentityKey(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  return crypto.generateKeyPairSync("ed25519");
}

/**
 * STEP 2: Signed PreKey (DH, X25519)
 */
function generateSignedPreKey(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  return crypto.generateKeyPairSync("x25519");
}

/**
 * STEP 3: Firma della Signed PreKey con identity key
 */
function signPreKey(
  identityPrivateKey: KeyObject,
  signedPreKeyPublic: KeyObject
): Buffer {
  return crypto.sign(
    null, // Ed25519 NON usa hash esterni
    Buffer.from(signedPreKeyPublic.export({ type: "spki", format: "der" })),
    identityPrivateKey
  );
}

/**
 * Genera OPK (one-time prekeys) DH
 */
function generateOneTimePreKeys(count: number) {
  const priv: KeyObject[] = [];
  const pub: KeyObject[] = [];
  for (let i = 0; i < count; i++) {
    const k = crypto.generateKeyPairSync("x25519");
    priv.push(k.privateKey);
    pub.push(k.publicKey);
  }
  return { privateKeys: priv, publicKeys: pub };
}

/**
 * STEP 1–3: Creazione di tutte le chiavi di Bob (Fester) e upload al server
 */
async function generateKeysAndPre() {
  // Identity key
  const identityKey = generateIdentityKey();

  // Signed PreKey
  const signedPreKey = generateSignedPreKey();

  // Firma della Signed PreKey
  const signature = signPreKey(identityKey.privateKey, signedPreKey.publicKey);

  // OPK
  const oneTimePreKeys = generateOneTimePreKeys(5); // esempio 5 chiavi usa-e-getta

  // Cosa va al server (pubbliche)
  const uploadToServer = {
    identityPublicKey: identityKey.publicKey.export({
      type: "spki",
      format: "der",
    }),
    signedPreKeyPublic: signedPreKey.publicKey.export({
      type: "spki",
      format: "der",
    }),
    signedPreKeySignature: signature,
    oneTimePreKeysPublic: oneTimePreKeys.publicKeys.map((k) =>
      k.export({ type: "spki", format: "der" })
    ),
  };

  // Cosa resta sul dispositivo (private)
  const localStorage = {
    identityPrivateKey: identityKey.privateKey,
    signedPreKeyPrivate: signedPreKey.privateKey,
    oneTimePreKeysPrivate: oneTimePreKeys.privateKeys,
  };

  console.log("STEP 1–3 completati");
  return { uploadToServer, localStorage };
}

/**
 * Herbert vuole inviare un messaggio a Bob
 */
export async function doubleRatchetTest() {
  // Simula server con le chiavi di Bob
  const fester = await generateKeysAndPre();
  const serverResponse = fester.uploadToServer;

  // Herbert genera chiave temporanea (ephemeral) per X3DH
  const ephemeralHerbert = crypto.generateKeyPairSync("x25519");

  // VERIFICA FIRMA della signed prekey di Bob
  const identityPubBob = crypto.createPublicKey({
    key: serverResponse.identityPublicKey,
    format: "der",
    type: "spki",
  });
  const signedPreKeyPubBob = crypto.createPublicKey({
    key: serverResponse.signedPreKeyPublic,
    format: "der",
    type: "spki",
  });

  const isValid = crypto.verify(
    null,
    Buffer.from(signedPreKeyPubBob.export({ type: "spki", format: "der" })),
    identityPubBob,
    serverResponse.signedPreKeySignature
  );

  if (!isValid) throw new Error("Firma della signed prekey non valida!");

  // Calcolo Diffie-Hellman (X3DH-lite)
  const DH1 = crypto.diffieHellman({
    privateKey: ephemeralHerbert.privateKey,
    publicKey: signedPreKeyPubBob,
  });

  // Opzionale: se vogliamo usare OPK
  let DH2: Buffer | null = null;
  if (serverResponse.oneTimePreKeysPublic.length > 0) {
    const OPK_pub = crypto.createPublicKey({
      key: serverResponse.oneTimePreKeysPublic[0],
      format: "der",
      type: "spki",
    });
    DH2 = crypto.diffieHellman({
      privateKey: ephemeralHerbert.privateKey,
      publicKey: OPK_pub,
    });
  }

  // Deriva sharedSecret iniziale
  const sharedSecret0 = crypto
    .createHash("sha256")
    .update(DH2 ? Buffer.concat([DH1, DH2]) : DH1)
    .digest();

  console.log(
    "Shared secret iniziale calcolato:",
    sharedSecret0.toString("hex")
  );
}

doubleRatchetTest();
