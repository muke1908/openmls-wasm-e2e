/**
 * Tests for the OpenMLS WASM E2E encryption/decryption wrapper.
 *
 * These tests verify the TypeScript API works correctly with the WASM module.
 * Run after building the WASM module: npm run build:wasm && npm test
 */

import { MlsClient, MlsEncryptionGroup, initOpenMls, OpenMlsWasmModule } from "../src/index.js";

describe("OpenMLS WASM E2E", () => {
  let wasm: OpenMlsWasmModule;

  beforeAll(async () => {
    wasm = await initOpenMls();
  });

  describe("MlsClient", () => {
    it("should create a client with a name", () => {
      const client = new MlsClient(wasm, "test-user");
      expect(client.getName()).toBe("test-user");
      client.free();
    });

    it("should generate a key package", () => {
      const client = new MlsClient(wasm, "test-user");
      const keyPackage = client.generateKeyPackage();
      expect(keyPackage).toBeInstanceOf(Uint8Array);
      expect(keyPackage.length).toBeGreaterThan(0);
      client.free();
    });
  });

  describe("MlsEncryptionGroup", () => {
    it("should create a group", () => {
      const client = new MlsClient(wasm, "founder");
      const group = MlsEncryptionGroup.create(client, "test-group");
      expect(group.getGroupId()).toBe("test-group");
      group.free();
      client.free();
    });

    it("should add a member and allow them to join", () => {
      const alice = new MlsClient(wasm, "alice");
      const bob = new MlsClient(wasm, "bob");

      const aliceGroup = MlsEncryptionGroup.create(alice, "chat");
      const bobKeyPackage = bob.generateKeyPackage();
      const { welcome, ratchetTree } = aliceGroup.addMember(bobKeyPackage);

      expect(welcome.length).toBeGreaterThan(0);
      expect(ratchetTree.length).toBeGreaterThan(0);

      const bobGroup = MlsEncryptionGroup.join(bob, welcome, ratchetTree, "chat");
      expect(bobGroup.getGroupId()).toBe("chat");

      bobGroup.free();
      aliceGroup.free();
      bob.free();
      alice.free();
    });
  });

  describe("Encrypt/Decrypt", () => {
    let alice: MlsClient;
    let bob: MlsClient;
    let aliceGroup: MlsEncryptionGroup;
    let bobGroup: MlsEncryptionGroup;

    beforeEach(() => {
      alice = new MlsClient(wasm, "alice");
      bob = new MlsClient(wasm, "bob");

      aliceGroup = MlsEncryptionGroup.create(alice, "e2e-test");
      const bobKp = bob.generateKeyPackage();
      const { welcome, ratchetTree } = aliceGroup.addMember(bobKp);
      bobGroup = MlsEncryptionGroup.join(bob, welcome, ratchetTree, "e2e-test");
    });

    afterEach(() => {
      bobGroup.free();
      aliceGroup.free();
      bob.free();
      alice.free();
    });

    it("should encrypt and decrypt a string message", () => {
      const message = "Hello, this is a secret!";
      const ciphertext = aliceGroup.encrypt(message);

      expect(ciphertext).toBeInstanceOf(Uint8Array);
      expect(ciphertext.length).toBeGreaterThan(0);

      const decrypted = bobGroup.decryptToString(ciphertext);
      expect(decrypted).toBe(message);
    });

    it("should encrypt and decrypt binary data", () => {
      const data = new Uint8Array([0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd]);
      const ciphertext = aliceGroup.encrypt(data);
      const decrypted = bobGroup.decrypt(ciphertext);

      expect(decrypted).toEqual(data);
    });

    it("should support bidirectional messaging", () => {
      const msg1 = "Hello from Alice!";
      const ct1 = aliceGroup.encrypt(msg1);
      expect(bobGroup.decryptToString(ct1)).toBe(msg1);

      const msg2 = "Hello from Bob!";
      const ct2 = bobGroup.encrypt(msg2);
      expect(aliceGroup.decryptToString(ct2)).toBe(msg2);
    });

    it("should handle multiple messages in sequence", () => {
      const messages = [
        "First message",
        "Second message",
        "Third message with special chars: 🔐🔑",
      ];

      for (const msg of messages) {
        const ct = aliceGroup.encrypt(msg);
        const decrypted = bobGroup.decryptToString(ct);
        expect(decrypted).toBe(msg);
      }
    });

    it("should produce different ciphertexts for the same plaintext", () => {
      const message = "Same message";
      const ct1 = aliceGroup.encrypt(message);
      const ct2 = aliceGroup.encrypt(message);

      // MLS uses ratcheting, so each ciphertext should be different
      expect(ct1).not.toEqual(ct2);
    });
  });
});
