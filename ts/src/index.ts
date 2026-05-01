/**
 * OpenMLS WASM E2E - TypeScript wrapper for OpenMLS WASM module
 *
 * Provides a high-level API for end-to-end encryption/decryption
 * using the MLS (Messaging Layer Security) protocol via WebAssembly.
 */

import type {
  OpenMlsWasmModule,
  WasmGroup,
  WasmIdentity,
  WasmProvider,
  WasmRatchetTree,
  WasmKeyPackage,
} from "./wasm-types.js";

/**
 * MlsClient represents a participant in an MLS group.
 * Each client has an identity (credential + signing keys) and a crypto provider.
 */
export class MlsClient {
  private provider: WasmProvider;
  private identity: WasmIdentity;
  private name: string;
  private wasmModule: OpenMlsWasmModule;

  constructor(wasmModule: OpenMlsWasmModule, name: string) {
    this.wasmModule = wasmModule;
    this.name = name;
    this.provider = new wasmModule.Provider();
    this.identity = new wasmModule.Identity(this.provider, name);
  }

  /** Get the client's display name */
  getName(): string {
    return this.name;
  }

  /** Generate a key package for joining groups */
  generateKeyPackage(): Uint8Array {
    const kp = this.identity.key_package(this.provider);
    const bytes = kp.to_bytes();
    kp.free();
    return bytes;
  }

  /** Get the raw provider (for internal use) */
  getProvider(): WasmProvider {
    return this.provider;
  }

  /** Get the raw identity (for internal use) */
  getIdentity(): WasmIdentity {
    return this.identity;
  }

  /** Get the WASM module reference */
  getWasmModule(): OpenMlsWasmModule {
    return this.wasmModule;
  }

  /** Clean up WASM resources */
  free(): void {
    this.identity.free();
    this.provider.free();
  }
}

/**
 * MlsEncryptionGroup wraps an MLS group and provides
 * encrypt/decrypt operations for group messaging.
 */
export class MlsEncryptionGroup {
  private group: WasmGroup;
  private client: MlsClient;
  private groupId: string;

  private constructor(group: WasmGroup, client: MlsClient, groupId: string) {
    this.group = group;
    this.client = client;
    this.groupId = groupId;
  }

  /** Create a new MLS group (the creator is the first member) */
  static create(client: MlsClient, groupId: string): MlsEncryptionGroup {
    const wasm = client.getWasmModule();
    const group = wasm.Group.create_new(
      client.getProvider(),
      client.getIdentity(),
      groupId
    );
    return new MlsEncryptionGroup(group, client, groupId);
  }

  /** Join an existing group using a welcome message and ratchet tree */
  static join(
    client: MlsClient,
    welcomeBytes: Uint8Array,
    ratchetTreeBytes: Uint8Array,
    groupId: string
  ): MlsEncryptionGroup {
    const wasm = client.getWasmModule();
    const ratchetTree = wasm.RatchetTree.from_bytes(ratchetTreeBytes);
    const group = wasm.Group.join(client.getProvider(), welcomeBytes, ratchetTree);
    return new MlsEncryptionGroup(group, client, groupId);
  }

  /** Get the group identifier */
  getGroupId(): string {
    return this.groupId;
  }

  /**
   * Add a new member to the group.
   * Returns the welcome message and ratchet tree bytes needed for the new member to join.
   */
  addMember(memberKeyPackageBytes: Uint8Array): {
    welcome: Uint8Array;
    ratchetTree: Uint8Array;
  } {
    const wasm = this.client.getWasmModule();
    const keyPackage = wasm.KeyPackage.from_bytes(memberKeyPackageBytes);
    const addMsgs = this.group.add_member(
      this.client.getProvider(),
      this.client.getIdentity(),
      keyPackage
    );

    const welcome = new Uint8Array(addMsgs.welcome);

    // Merge the pending commit to update our group state
    this.group.merge_pending_commit(this.client.getProvider());

    // Export ratchet tree for the new member
    const ratchetTreeObj = this.group.export_ratchet_tree();
    const ratchetTree = ratchetTreeObj.to_bytes();
    ratchetTreeObj.free();

    keyPackage.free();
    addMsgs.free();

    return { welcome, ratchetTree };
  }

  /**
   * Encrypt a message for the group.
   * Returns the encrypted MLS ciphertext bytes.
   */
  encrypt(plaintext: string | Uint8Array): Uint8Array {
    const data =
      typeof plaintext === "string"
        ? new TextEncoder().encode(plaintext)
        : plaintext;

    return this.group.encrypt(
      this.client.getProvider(),
      this.client.getIdentity(),
      data
    );
  }

  /**
   * Decrypt a message received from the group.
   * Returns the decrypted plaintext bytes.
   */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    return this.group.decrypt(this.client.getProvider(), ciphertext);
  }

  /**
   * Decrypt a message and return it as a UTF-8 string.
   */
  decryptToString(ciphertext: Uint8Array): string {
    const bytes = this.decrypt(ciphertext);
    return new TextDecoder().decode(bytes);
  }

  /** Clean up WASM resources */
  free(): void {
    this.group.free();
  }
}

/**
 * Initialize the OpenMLS WASM module.
 * This function loads and returns the WASM module ready for use.
 *
 * @param wasmModulePath - Path or package name to import the WASM module from.
 *   Defaults to '../pkg/openmls_wasm.js' which assumes the WASM package was built
 *   to 'ts/pkg/' via `npm run build:wasm`. When used as a published package or
 *   in different project layouts, provide the correct path or package name.
 */
export async function initOpenMls(
  wasmModulePath?: string
): Promise<OpenMlsWasmModule> {
  const modulePath = wasmModulePath || "../pkg/openmls_wasm.js";
  const module = await import(modulePath);
  return module as unknown as OpenMlsWasmModule;
}

export type { OpenMlsWasmModule } from "./wasm-types.js";
