/**
 * OpenMLS WASM E2E Demo
 *
 * Demonstrates end-to-end encryption and decryption using the MLS protocol
 * via the OpenMLS WASM module.
 *
 * Usage:
 *   1. Build the WASM module: npm run build:wasm
 *   2. Run this demo: npm run demo
 */

import { MlsClient, MlsEncryptionGroup, initOpenMls } from "./index.js";

async function main() {
  console.log("=== OpenMLS WASM E2E Encryption Demo ===\n");

  // Step 1: Initialize the WASM module
  console.log("1. Initializing OpenMLS WASM module...");
  const wasm = await initOpenMls();
  console.log("   ✓ WASM module loaded\n");

  // Step 2: Create two clients (Alice and Bob)
  console.log("2. Creating MLS clients...");
  const alice = new MlsClient(wasm, "alice");
  const bob = new MlsClient(wasm, "bob");
  console.log(`   ✓ Created client: ${alice.getName()}`);
  console.log(`   ✓ Created client: ${bob.getName()}\n`);

  // Step 3: Bob generates a key package (needed to be added to a group)
  console.log("3. Bob generates a key package...");
  const bobKeyPackage = bob.generateKeyPackage();
  console.log(`   ✓ Key package generated (${bobKeyPackage.length} bytes)\n`);

  // Step 4: Alice creates a group
  console.log('4. Alice creates an MLS group "secret-chat"...');
  const aliceGroup = MlsEncryptionGroup.create(alice, "secret-chat");
  console.log(`   ✓ Group "${aliceGroup.getGroupId()}" created\n`);

  // Step 5: Alice adds Bob to the group
  console.log("5. Alice adds Bob to the group...");
  const { welcome, ratchetTree } = aliceGroup.addMember(bobKeyPackage);
  console.log(`   ✓ Welcome message generated (${welcome.length} bytes)`);
  console.log(`   ✓ Ratchet tree exported (${ratchetTree.length} bytes)\n`);

  // Step 6: Bob joins the group using the welcome message
  console.log("6. Bob joins the group...");
  const bobGroup = MlsEncryptionGroup.join(bob, welcome, ratchetTree, "secret-chat");
  console.log("   ✓ Bob successfully joined the group\n");

  // Step 7: Alice encrypts a message
  const message = "Hello Bob! This is a secret message encrypted with MLS.";
  console.log("7. Alice encrypts a message...");
  console.log(`   Plaintext: "${message}"`);
  const ciphertext = aliceGroup.encrypt(message);
  console.log(`   ✓ Encrypted (${ciphertext.length} bytes of ciphertext)\n`);

  // Step 8: Bob decrypts the message
  console.log("8. Bob decrypts the message...");
  const decrypted = bobGroup.decryptToString(ciphertext);
  console.log(`   ✓ Decrypted: "${decrypted}"\n`);

  // Step 9: Verify the message matches
  console.log("9. Verifying...");
  if (decrypted === message) {
    console.log("   ✓ SUCCESS: Decrypted message matches the original!\n");
  } else {
    console.error("   ✗ FAILURE: Messages don't match!\n");
    process.exit(1);
  }

  // Step 10: Bob sends a reply (bidirectional encryption)
  const reply = "Hi Alice! Got your secret message. MLS encryption works!";
  console.log("10. Bob encrypts a reply...");
  console.log(`    Plaintext: "${reply}"`);
  const replyCiphertext = bobGroup.encrypt(reply);
  console.log(`    ✓ Encrypted (${replyCiphertext.length} bytes)\n`);

  console.log("11. Alice decrypts Bob's reply...");
  const decryptedReply = aliceGroup.decryptToString(replyCiphertext);
  console.log(`    ✓ Decrypted: "${decryptedReply}"\n`);

  if (decryptedReply === reply) {
    console.log("    ✓ SUCCESS: Bidirectional encryption verified!\n");
  } else {
    console.error("    ✗ FAILURE: Reply doesn't match!\n");
    process.exit(1);
  }

  // Cleanup
  aliceGroup.free();
  bobGroup.free();
  alice.free();
  bob.free();

  console.log("=== Demo Complete ===");
  console.log("MLS end-to-end encryption/decryption working correctly!");
}

main().catch((err) => {
  console.error("Demo failed:", err);
  process.exit(1);
});
