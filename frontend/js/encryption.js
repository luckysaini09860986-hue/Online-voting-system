// WebCrypto API — runs entirely client-side, like WhatsApp
export async function generateVoterKeypair() {
  return await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true, ["deriveKey", "deriveBits"]
  );
}

export async function encryptVote(voteChoice, electionPublicKeyJwk) {
  // 1. Import election public key
  const electionPubKey = await crypto.subtle.importKey(
    "jwk", electionPublicKeyJwk,
    { name: "ECDH", namedCurve: "P-256" }, false, []
  );
  // 2. Voter ephemeral keypair
  const voterKeypair = await generateVoterKeypair();
  // 3. Derive shared secret via ECDH
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: electionPubKey },
    voterKeypair.privateKey, 256
  );
  // 4. AES-256-GCM encrypt
  const aesKey = await crypto.subtle.importKey(
    "raw", sharedBits, { name: "AES-GCM" }, false, ["encrypt"]
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    aesKey, encoder.encode(voteChoice)
  );
  // 5. Export voter ephemeral public key (sent to server, NOT private key)
  const voterPubJwk = await crypto.subtle.exportKey("jwk", voterKeypair.publicKey);
  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    nonce: btoa(String.fromCharCode(...nonce)),
    voter_ephemeral_pub: voterPubJwk,
    scheme: "ECDH-AES256-GCM"
  };
}