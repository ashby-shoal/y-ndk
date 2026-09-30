import { ObservableV2 } from "lib0/observable";
import { toBase64, fromBase64 } from "lib0/buffer";
import { NDKEvent } from "@nostr-dev-kit/ndk";
import { finalizeEvent, verifyEvent } from "nostr-tools/pure";
import { SimplePool } from "nostr-tools/pool";

import {
  arrayBuffersAreEqual,
  snapshotContainsAllDeletes,
} from "./util.mjs";

const pool = new SimplePool();

const NOSTR_UPDATE_CHUNK_BYTES = 512 * 1024;
const NOSTR_ROOM_CONTROL_EVENT_KIND = 7778;
const DEFAULT_ROOM_MIGRATION_UPDATE_THRESHOLD = 500;
const DEFAULT_ROOM_MIGRATION_BYTE_THRESHOLD = 2 * 1024 * 1024;

const ENC_TAG_NAME = "enc";
const ENC_AGE = "age";

/* -------------------------------------------------------------------------- */
/* Binary helpers                                                             */
/* -------------------------------------------------------------------------- */

function toUint8Array(value) {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(
      value.buffer,
      value.byteOffset,
      value.byteLength,
    );
  }

  if (typeof value === "string") {
    return new TextEncoder().encode(value);
  }

  if (value == null) {
    throw new Error(
      "Cannot convert null/undefined value to Uint8Array",
    );
  }

  return new Uint8Array(value);
}

function normalizeDecryptedValue(value) {
  return toUint8Array(value);
}

function randomId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  // UUID v4
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes, (b) =>
    b.toString(16).padStart(2, "0")
  ).join("");

  return (
    hex.slice(0, 8) + "-" +
    hex.slice(8, 12) + "-" +
    hex.slice(12, 16) + "-" +
    hex.slice(16, 20) + "-" +
    hex.slice(20)
  );
}

function getEncryptionTag(encrypted) {
  return encrypted ? [ENC_TAG_NAME, ENC_AGE] : undefined;
}

function hasAgeEncryptionTag(event) {
  return (
    event?.tags?.some(
      (tag) =>
        Array.isArray(tag) &&
        tag[0] === ENC_TAG_NAME &&
        tag[1] === ENC_AGE,
    ) === true
  );
}

function addEncryptionTag(tags, encrypted) {
  if (!encrypted) {
    return tags;
  }

  if (
    tags.some(
      (tag) =>
        Array.isArray(tag) &&
        tag[0] === ENC_TAG_NAME,
    )
  ) {
    return tags;
  }

  return [...tags, getEncryptionTag(true)];
}

/* -------------------------------------------------------------------------- */
/* Chunking                                                                   */
/* -------------------------------------------------------------------------- */

function splitUpdatesIntoChunks(
  yjs,
  updates,
  maxBytes = NOSTR_UPDATE_CHUNK_BYTES,
) {
  const chunks = [];

  let current = [];
  let currentSize = 0;

  for (const update of updates) {
    const bytes = toUint8Array(update);
    const size = bytes.byteLength;

    if (size > maxBytes) {
      throw new Error(
        `A single Yjs update is ${size} bytes, which exceeds ` +
          `${maxBytes} bytes. A single Yjs update cannot safely be split.`,
      );
    }

    if (
      current.length > 0 &&
      currentSize + size > maxBytes
    ) {
      chunks.push(
        toUint8Array(
          yjs.mergeUpdates(current),
        ),
      );

      current = [];
      currentSize = 0;
    }

    current.push(bytes);
    currentSize += size;
  }

  if (current.length > 0) {
    chunks.push(
      toUint8Array(
        yjs.mergeUpdates(current),
      ),
    );
  }

  return chunks;
}

function createChunkTag(batchId, index, total) {
  return [
    "chunk",
    batchId,
    String(index),
    String(total),
  ];
}

/* -------------------------------------------------------------------------- */
/* Encryption callbacks                                                       */
/* -------------------------------------------------------------------------- */

async function runEncrypt(encrypt, input) {
  if (typeof encrypt !== "function") {
    throw new Error(
      "[YJS] encrypt() function is not configured",
    );
  }

  const result = await encrypt(input);

  if (
    !result ||
    typeof result !== "object" ||
    !("data" in result)
  ) {
    throw new Error(
      "[YJS] encrypt() must return { data, encrypted }",
    );
  }

  const data = toUint8Array(result.data);

  if (data.byteLength === 0) {
    throw new Error(
      "[YJS] encrypt() returned empty data",
    );
  }

  return {
    data,
    encrypted: result.encrypted === true,
  };
}

async function runDecrypt(
  decrypt,
  input,
  encrypted,
) {
  /*
   * The event itself determines whether decryption is required.
   *
   * Plaintext event:
   *   return the original bytes untouched.
   *
   * Encrypted event:
   *   call the decrypt callback supplied by the application.
   *
   * y-ndk deliberately knows nothing about age identities,
   * recipients, keys, or encryption configuration.
   */

  if (!encrypted) {
    return toUint8Array(input);
  }

  /*
   * An encrypted event is valid Nostr/Yjs data, but this particular
   * client may intentionally be operating in plaintext mode.
   *
   * Do NOT pass ciphertext through as plaintext.
   *
   * Returning undefined from runDecrypt() lets callers distinguish
   * "not decryptable by this client" from a successful plaintext
   * decode.
   */
  if (typeof decrypt !== "function") {
    return undefined;
  }

  /*
   * The application owns all crypto state through the closure.
   *
   * y-ndk passes ONLY the ciphertext.
   */
  const result = await decrypt(input);

  /*
   * A configured decrypt function returning undefined/null is different
   * from having no decrypt function at all. It indicates that the caller's
   * crypto implementation could not produce plaintext.
   */
  if (result == null) {
    throw new Error(
      "[YJS] decrypt() returned null/undefined",
    );
  }

  const output = normalizeDecryptedValue(result);

  if (output.byteLength === 0) {
    throw new Error(
      "[YJS] decrypt() returned empty data",
    );
  }

  return output;
}

/* -------------------------------------------------------------------------- */
/* Nostr publishing                                                           */
/* -------------------------------------------------------------------------- */

async function publishEvent({
  ndk,
  explicitRelayUrls,
  secretNostrKey,
  eventTemplate,
}) {
  if (!eventTemplate.kind) {
    throw new Error(
      "Cannot publish Nostr event without kind",
    );
  }

  if (!eventTemplate.tags) {
    eventTemplate.tags = [];
  }

  if (eventTemplate.content === undefined) {
    throw new Error(
      "Cannot publish Nostr event without content",
    );
  }

  if (secretNostrKey !== undefined) {
    const signedEvent = finalizeEvent(
      eventTemplate,
      secretNostrKey,
    );

    if (!verifyEvent(signedEvent)) {
      throw new Error(
        "Failed to verify signed Nostr event",
      );
    }

    await pool.publish(
      explicitRelayUrls || [],
      signedEvent,
    );

    return signedEvent;
  }

  const event = new NDKEvent(
    ndk,
    eventTemplate,
  );

  await event.publish();

  return event;
}

/* -------------------------------------------------------------------------- */
/* Room migration                                                             */
/* -------------------------------------------------------------------------- */

function parseRoomControlEvent(event) {
  if (event?.kind !== NOSTR_ROOM_CONTROL_EVENT_KIND) {
    return undefined;
  }

  const actionTag = event.tags?.find(
    (tag) =>
      Array.isArray(tag) &&
      tag[0] === "action",
  );

  if (actionTag?.[1] !== "deprecated") {
    return undefined;
  }

  const roomTag = event.tags?.find(
    (tag) =>
      Array.isArray(tag) &&
      tag[0] === "room",
  );

  const newRoomId = `${roomTag?.[1] ?? ""}`.trim();

  if (!newRoomId) {
    return undefined;
  }

  return {
    action: "deprecated",
    oldRoomId: event.tags?.find(
      (tag) =>
        Array.isArray(tag) &&
        tag[0] === "e",
    )?.[1] ?? "",
    newRoomId,
    eventId: event.id,
  };
}

export async function publishRoomDeprecated({
  ndk,
  explicitRelayUrls,
  secretNostrKey,
  oldRoomId,
  newRoomId,
}) {
  const event = await publishEvent({
    ndk,
    explicitRelayUrls,
    secretNostrKey,
    eventTemplate: {
      kind: NOSTR_ROOM_CONTROL_EVENT_KIND,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["e", oldRoomId],
        ["room", newRoomId],
        ["action", "deprecated"],
      ],
      content: JSON.stringify({
        action: "deprecated",
        oldRoomId,
        newRoomId,
      }),
    },
  });

  return event.id;
}

export async function migrateNostrCRDTRoom({
  ndk,
  yjs,
  ydoc,
  label,
  oldRoomId,
  YJS_UPDATE_EVENT_KIND,
  secretNostrKey,
  explicitRelayUrls,
  encrypt,
}) {
  if (!oldRoomId) {
    throw new Error(
      "[YJS] Cannot migrate room without oldRoomId",
    );
  }

  const snapshot = toUint8Array(
    yjs.encodeStateAsUpdate(ydoc),
  );

  if (snapshot.byteLength <= 2) {
    throw new Error(
      "[YJS] Cannot migrate an empty room",
    );
  }

  const newRoomId = await createNostrCRDTRoom({
    ndk,
    yjs,
    label: label || "crdtroom",
    initialLocalState: snapshot,
    YJS_UPDATE_EVENT_KIND,
    secretNostrKey,
    explicitRelayUrls,
    encrypt,
  });

  if (!newRoomId) {
    throw new Error(
      "[YJS] Room migration did not produce a new room ID",
    );
  }

  await publishRoomDeprecated({
    ndk,
    explicitRelayUrls,
    secretNostrKey,
    oldRoomId,
    newRoomId,
  });

  return newRoomId;
}

/* -------------------------------------------------------------------------- */
/* Create room                                                                */
/* -------------------------------------------------------------------------- */

export async function createNostrCRDTRoom(params) {
  const {
    ndk,
    label,
    initialLocalState,
    YJS_UPDATE_EVENT_KIND,
    secretNostrKey,
    explicitRelayUrls,
    encrypt = async (value) => ({
      data: value,
      encrypted: false,
    }),
    yjs,
  } = params;

  if (!yjs) {
    const encrypted = await runEncrypt(
      encrypt,
      toUint8Array(initialLocalState),
    );

    const tags = [["crdt", label]];

    const event = await publishEvent({
      ndk,
      explicitRelayUrls,
      secretNostrKey,
      eventTemplate: {
        kind: YJS_UPDATE_EVENT_KIND,
        created_at: Math.floor(Date.now() / 1000),
        tags: addEncryptionTag(
          tags,
          encrypted.encrypted,
        ),
        content: toBase64(encrypted.data),
      },
    });

    return event.id;
  }

  const initialChunks =
    splitUpdatesIntoChunks(
      yjs,
      [initialLocalState],
      NOSTR_UPDATE_CHUNK_BYTES,
    );

  if (initialChunks.length === 0) {
    throw new Error(
      "Cannot create Yjs room from an empty update",
    );
  }

  const batchId = randomId();
  const total = initialChunks.length;

  const encryptedFirst = await runEncrypt(
    encrypt,
    initialChunks[0],
  );

  const firstTags = addEncryptionTag(
    [
      ["crdt", label],
      createChunkTag(batchId, 0, total),
    ],
    encryptedFirst.encrypted,
  );

  const firstEvent = await publishEvent({
    ndk,
    explicitRelayUrls,
    secretNostrKey,
    eventTemplate: {
      kind: YJS_UPDATE_EVENT_KIND,
      created_at: Math.floor(Date.now() / 1000),
      tags: firstTags,
      content: toBase64(encryptedFirst.data),
    },
  });

  const roomId = firstEvent.id;

  if (!roomId) {
    throw new Error(
      "Nostr room creation event did not have an event ID",
    );
  }

  for (
    let i = 1;
    i < initialChunks.length;
    i++
  ) {
    const encrypted = await runEncrypt(
      encrypt,
      initialChunks[i],
    );

    const tags = addEncryptionTag(
      [
        ["e", roomId],
        createChunkTag(batchId, i, total),
      ],
      encrypted.encrypted,
    );

    await publishEvent({
      ndk,
      explicitRelayUrls,
      secretNostrKey,
      eventTemplate: {
        kind: YJS_UPDATE_EVENT_KIND,
        created_at: Math.floor(Date.now() / 1000),
        tags,
        content: toBase64(encrypted.data),
      },
    });
  }

  return roomId;
}

/* -------------------------------------------------------------------------- */
/* NostrProvider                                                              */
/* -------------------------------------------------------------------------- */

export class NostrProvider extends ObservableV2 {
  constructor(params) {
    const {
      yjs,
      ydoc,
      nostrRoomCreateEventId,
      ndk,
      YJS_UPDATE_EVENT_KIND,
      secretNostrKey,
      explicitRelayUrls,
      label = "crdtroom",
      autoMigrate = true,
      migrationUpdateThreshold =
        DEFAULT_ROOM_MIGRATION_UPDATE_THRESHOLD,
      migrationByteThreshold =
        DEFAULT_ROOM_MIGRATION_BYTE_THRESHOLD,
      onRoomDeprecated = undefined,

      /*
       * ONLY callbacks cross the y-ndk boundary.
       *
       * Any encryption state, age identities, recipients, keys,
       * or other crypto configuration belongs to the caller.
       */
      encrypt = async (value) => ({
        data: value,
        encrypted: false,
      }),
      decrypt = undefined,
    } = params;

    super();

    this.yjs = yjs;
    this.ydoc = ydoc;
    this.ndk = ndk;

    this.nostrRoomCreateEventId =
      nostrRoomCreateEventId;

    this.YJS_UPDATE_EVENT_KIND =
      YJS_UPDATE_EVENT_KIND;

    this.secretNostrKey =
      secretNostrKey;

    this.explicitRelayUrls =
      explicitRelayUrls || [];

    this.label = label;
    this.autoMigrate = autoMigrate === true;
    this.migrationUpdateThreshold =
      Math.max(1, migrationUpdateThreshold);
    this.migrationByteThreshold =
      Math.max(1, migrationByteThreshold);
    this.onRoomDeprecated =
      typeof onRoomDeprecated === "function"
        ? onRoomDeprecated
        : undefined;

    this.encrypt = encrypt;
    this.decrypt = decrypt;

    this.localUpdateCount = 0;
    this.localUpdateBytes = 0;
    this.migrationInProgress = false;
    this.migrated = false;

    this.chunkBuffer = new Map();
    this.chunkBufferMaxAge = 60 * 60 * 1000;
    this.pendingUpdates = [];
    this.sendPendingTimeout = undefined;

    this.destroyed = false;
    this.subscription = undefined;

    this._documentUpdateListener = (
      update,
      origin,
    ) => {
      void this.documentUpdateListener(
        update,
        origin,
      );
    };

    this.ydoc.on(
      "update",
      this._documentUpdateListener,
    );
  }

  /* ------------------------------------------------------------------------ */
  /* Decode events                                                            */
  /* ------------------------------------------------------------------------ */

  async decodeEvent(event) {
    const encoded = fromBase64(event.content);

    const encrypted =
      hasAgeEncryptionTag(event);

    const update = await runDecrypt(
      this.decrypt,
      encoded,
      encrypted,
    );

    if (update == null) {
      return undefined;
    }

    return update;
  }

  async updateFromEvents(events) {
    const updates = [];

    for (const event of events) {
      try {
        const update =
          await this.decodeEvent(event);

        if (update == null) {
          continue;
        }

        if (update.byteLength === 0) {
          continue;
        }

        updates.push(update);
      } catch (error) {
        // console.error(
        //   "[YJS] Failed to decode/decrypt event:",
        //   {
        //     eventId: event?.id,
        //     error,
        //   },
        // );
      }
    }

    try {
      return toUint8Array(
        this.yjs.mergeUpdates(updates),
      );
    } catch (error) {
      console.error(
        "[YJS] mergeUpdates() failed",
        {
          updateCount: updates.length,
          updateSizes: updates.map(
            (update) =>
              update.byteLength,
          ),
          firstBytes: updates.map(
            (update) =>
              Array.from(
                update.slice(0, 32),
              ),
          ),
          error,
        },
      );

      throw error;
    }
  }

  async switchToRoom(newRoomId) {
    if (
      !newRoomId ||
      newRoomId ===
        this.nostrRoomCreateEventId ||
      this.destroyed
    ) {
      return;
    }

    this.nostrRoomCreateEventId =
      newRoomId;

    this.localUpdateCount = 0;
    this.localUpdateBytes = 0;
    this.migrationInProgress = false;
    this.migrated = false;

    try {
      for (const sub of this.subscription || []) {
        sub?.stop?.();
        sub?.close?.();
        sub?.unsubscribe?.();
      }
    } catch (error) {
      console.warn(
        "[YJS] Failed to stop deprecated-room subscriptions:",
        error,
      );
    }

    this.subscription = undefined;

    /*
     * Start the new generation against the same Y.Doc.
     * IndexedDB and any local offline changes therefore remain intact.
     */
    await this.initialize();
  }

  async processRoomControlEvent(event) {
    const control = parseRoomControlEvent(event);

    if (!control) {
      return;
    }

    if (
      control.oldRoomId &&
      control.oldRoomId !==
        this.nostrRoomCreateEventId
    ) {
      return;
    }

    if (this.migrated) {
      return;
    }

    this.migrated = true;

    const oldRoomId =
      control.oldRoomId ||
      this.nostrRoomCreateEventId;

    try {
      await this.onRoomDeprecated?.(
        control.newRoomId,
        oldRoomId,
        control.eventId,
      );
    } catch (error) {
      console.warn(
        "[YJS] onRoomDeprecated callback failed:",
        error,
      );
    }

    if (!this.destroyed) {
      await this.switchToRoom(
        control.newRoomId,
      );
    }
  }

  async maybeMigrateRoom() {
    if (
      !this.autoMigrate ||
      this.destroyed ||
      this.migrationInProgress ||
      this.migrated ||
      this.pendingUpdates.length > 0
    ) {
      return;
    }

    if (
      this.localUpdateCount <
        this.migrationUpdateThreshold &&
      this.localUpdateBytes <
        this.migrationByteThreshold
    ) {
      return;
    }

    this.migrationInProgress = true;

    try {
      console.log(
        "[YJS] Migrating large room",
        {
          oldRoomId:
            this.nostrRoomCreateEventId,
          updateCount:
            this.localUpdateCount,
          updateBytes:
            this.localUpdateBytes,
        },
      );

      const newRoomId =
        await migrateNostrCRDTRoom({
          ndk: this.ndk,
          yjs: this.yjs,
          ydoc: this.ydoc,
          label: this.label,
          oldRoomId:
            this.nostrRoomCreateEventId,
          YJS_UPDATE_EVENT_KIND:
            this.YJS_UPDATE_EVENT_KIND,
          secretNostrKey:
            this.secretNostrKey,
          explicitRelayUrls:
            this.explicitRelayUrls,
          encrypt: this.encrypt,
        });

      const oldRoomId =
        this.nostrRoomCreateEventId;

      this.migrated = true;

      await this.onRoomDeprecated?.(
        newRoomId,
        oldRoomId,
        undefined,
      );

      if (!this.destroyed) {
        await this.switchToRoom(
          newRoomId,
        );
      }
    } catch (error) {
      console.warn(
        "[YJS] Room migration failed; continuing with current room:",
        error,
      );
    } finally {
      this.migrationInProgress = false;
    }
  }

  /* ------------------------------------------------------------------------ */
  /* Publish                                                                  */
  /* ------------------------------------------------------------------------ */

  async publishUpdate(update) {
    return this.publishUpdates([update]);
  }

  async publishUpdates(updates) {
    if (
      this.destroyed ||
      !updates ||
      updates.length === 0
    ) {
      return;
    }

    if (!this.nostrRoomCreateEventId) {
      throw new Error(
        "[YJS] Cannot publish update: nostrRoomCreateEventId is undefined",
      );
    }

    const chunks = splitUpdatesIntoChunks(
      this.yjs,
      updates,
      NOSTR_UPDATE_CHUNK_BYTES,
    );

    const batchId = randomId();
    const total = chunks.length;

    for (
      let i = 0;
      i < chunks.length;
      i++
    ) {
      const chunk = chunks[i];

      if (!(chunk instanceof Uint8Array)) {
        throw new Error(
          "[YJS] Chunk is not Uint8Array",
        );
      }

      if (chunk.byteLength === 0) {
        continue;
      }

      const encrypted = await runEncrypt(
        this.encrypt,
        chunk,
      );

      const content = toBase64(
        encrypted.data,
      );

      const tags = addEncryptionTag(
        [
          ["e", this.nostrRoomCreateEventId],
          createChunkTag(
            batchId,
            i,
            total,
          ),
        ],
        encrypted.encrypted,
      );

      await publishEvent({
        ndk: this.ndk,
        explicitRelayUrls:
          this.explicitRelayUrls,
        secretNostrKey:
          this.secretNostrKey,
        eventTemplate: {
          kind:
            this.YJS_UPDATE_EVENT_KIND,
          created_at:
            Math.floor(
              Date.now() / 1000,
            ),
          tags,
          content,
        },
      });
    }
  }

  /* ------------------------------------------------------------------------ */
  /* Local updates                                                            */
  /* ------------------------------------------------------------------------ */

  async documentUpdateListener(
    update,
    origin,
  ) {
    if (this.destroyed) {
      return;
    }

    if (origin === this) {
      return;
    }

    if (origin?.provider) {
      return;
    }

    const localUpdate =
      toUint8Array(update);

    this.localUpdateCount += 1;
    this.localUpdateBytes +=
      localUpdate.byteLength;

    this.pendingUpdates.push(
      localUpdate,
    );

    if (this.sendPendingTimeout) {
      clearTimeout(
        this.sendPendingTimeout,
      );
    }

    this.sendPendingTimeout =
      setTimeout(async () => {
        if (this.destroyed) {
          return;
        }

        const updates =
          this.pendingUpdates;

        this.pendingUpdates = [];
        this.sendPendingTimeout =
          undefined;

        try {
          await this.publishUpdates(
            updates,
          );

          await this.maybeMigrateRoom();
        } catch (error) {
          console.error(
            "[YJS] Failed to publish Yjs update:",
            error,
          );

          if (!this.destroyed) {
            this.pendingUpdates.unshift(
              ...updates,
            );
          }
        }
      }, 100);
  }

  /* ------------------------------------------------------------------------ */
  /* Chunk cleanup                                                             */
  /* ------------------------------------------------------------------------ */

  cleanupChunkBuffer() {
    const now = Date.now();

    for (
      const [batchId, batch] of
        this.chunkBuffer
    ) {
      if (
        now - batch.createdAt >
        this.chunkBufferMaxAge
      ) {
        this.chunkBuffer.delete(
          batchId,
        );
      }
    }
  }

  /* ------------------------------------------------------------------------ */
  /* Incoming event                                                           */
  /* ------------------------------------------------------------------------ */

  async processIncomingEvent(event) {
    if (this.destroyed) {
      return;
    }

    if (
      event?.kind ===
      NOSTR_ROOM_CONTROL_EVENT_KIND
    ) {
      await this.processRoomControlEvent(
        event,
      );

      return;
    }

    const chunkTag =
      event.tags?.find(
        (tag) =>
          tag[0] === "chunk",
      );

    if (!chunkTag) {
      try {
        const update =
          await this.decodeEvent(event);

        if (update == null) {
          return;
        }

        if (update.byteLength === 0) {
          return;
        }

        this.yjs.applyUpdate(
          this.ydoc,
          update,
          this,
        );
      } catch (error) {
        console.error(
          "[YJS] Failed to process incoming Yjs event:",
          {
            eventId: event?.id,
            error,
          },
        );
      }

      return;
    }

    const [
      ,
      batchId,
      indexString,
      totalString,
    ] = chunkTag;

    const index = Number(indexString);
    const total = Number(totalString);

    if (
      !batchId ||
      !Number.isInteger(index) ||
      !Number.isInteger(total) ||
      total <= 0 ||
      index < 0 ||
      index >= total
    ) {
      return;
    }

    this.cleanupChunkBuffer();

    let batch =
      this.chunkBuffer.get(batchId);

    if (!batch) {
      batch = {
        total,
        chunks: new Array(total),
        received: 0,
        createdAt: Date.now(),
      };

      this.chunkBuffer.set(
        batchId,
        batch,
      );
    }

    if (batch.total !== total) {
      return;
    }

    if (!batch.chunks[index]) {
      try {
        const update =
          await this.decodeEvent(event);

        if (update == null) {
          return;
        }

        if (update.byteLength === 0) {
          return;
        }

        batch.chunks[index] = update;
        batch.received += 1;
      } catch (error) {
        // console.error(
        //   "[YJS] Failed to decode/decrypt incoming chunk:",
        //   {
        //     eventId: event?.id,
        //     error,
        //   },
        // );

        return;
      }
    }

    if (batch.received !== batch.total) {
      return;
    }

    const chunks = batch.chunks;

    if (
      chunks.some(
        (chunk) =>
          !(chunk instanceof Uint8Array),
      )
    ) {
      return;
    }

    try {
      const merged =
        this.yjs.mergeUpdates(chunks);

      if (!(merged instanceof Uint8Array)) {
        throw new Error(
          "[YJS] mergeUpdates() did not return Uint8Array",
        );
      }

      if (merged.byteLength === 0) {
        return;
      }

      this.chunkBuffer.delete(batchId);

      this.yjs.applyUpdate(
        this.ydoc,
        merged,
        this,
      );
    } catch (error) {
      console.error(
        "[YJS] Failed to merge/apply incoming chunks:",
        {
          batchId,
          error,
        },
      );

      this.chunkBuffer.delete(batchId);
    }
  }

  processIncomingEvents(events) {
    for (const event of events) {
      void this.processIncomingEvent(
        event,
      );
    }
  }
  /* ------------------------------------------------------------------------ */
  /* Initial history                                                          */
  /* ------------------------------------------------------------------------ */

  updateFromInitialEvents(events) {
    const completeEvents = [];
    const batches = new Map();

    for (const event of events) {
      const chunkTag =
        event.tags?.find(
          (tag) =>
            tag[0] === "chunk",
        );

      if (!chunkTag) {
        completeEvents.push(event);
        continue;
      }

      const [
        ,
        batchId,
        indexString,
        totalString,
      ] = chunkTag;

      const index = Number(indexString);
      const total = Number(totalString);

      if (
        !batchId ||
        !Number.isInteger(index) ||
        !Number.isInteger(total) ||
        total <= 0 ||
        index < 0 ||
        index >= total
      ) {
        continue;
      }

      let batch = batches.get(batchId);

      if (!batch) {
        batch = {
          total,
          events: new Array(total),
          received: 0,
        };

        batches.set(
          batchId,
          batch,
        );
      }

      if (batch.total !== total) {
        continue;
      }

      if (
        batch.events[index] !==
        undefined
      ) {
        continue;
      }

      batch.events[index] = event;
      batch.received++;
    }

    for (
      const batch of batches.values()
    ) {
      if (
        batch.received !==
        batch.total
      ) {
        continue;
      }

      if (
        batch.events.some(
          (event) =>
            event === undefined,
        )
      ) {
        continue;
      }

      completeEvents.push(
        ...batch.events,
      );
    }

    return completeEvents;
  }

  /* ------------------------------------------------------------------------ */
  /* Initialize                                                               */
  /* ------------------------------------------------------------------------ */

  async initialize() {
    if (
      this.destroyed ||
      !this.nostrRoomCreateEventId
    ) {
      return;
    }

    try {
      let eoseCount = 0;
      let eoseSeen = false;
      const initialEvents = [];
      const initialEventIds = new Set();

      const subscriptions = [];

      const handleEvent = (event) => {
        if (this.destroyed) {
          return;
        }

        if (
          event?.kind ===
          NOSTR_ROOM_CONTROL_EVENT_KIND
        ) {
          void this.processRoomControlEvent(
            event,
          );

          return;
        }

        if (
          event?.id &&
          initialEventIds.has(event.id)
        ) {
          return;
        }

        if (event?.id) {
          initialEventIds.add(event.id);
        }

        if (!eoseSeen) {
          initialEvents.push(event);
        } else {
          void this.processIncomingEvent(
            event,
          );
        }
      };

      const handleEvents = (events) => {
        for (const event of events || []) {
          handleEvent(event);
        }
      };

      const handleEose = async () => {
        if (this.destroyed) {
          return;
        }

        eoseCount += 1;

        /*
         * We use two subscriptions:
         *
         * 1. ids = current room creation event
         * 2. #e = current room creation event
         *
         * Wait until both have reached EOSE before reconstructing
         * the initial state.
         */
        if (
          eoseCount < 2 ||
          eoseSeen
        ) {
          return;
        }

        eoseSeen = true;

        const usableInitialEvents =
          this.updateFromInitialEvents(
            initialEvents,
          );

        const initialLocalState =
          this.yjs.encodeStateAsUpdate(
            this.ydoc,
          );

        const initialLocalStateVector =
          this.yjs.encodeStateVectorFromUpdate(
            initialLocalState,
          );

        const deleteSetOnlyUpdate =
          this.yjs.diffUpdate(
            initialLocalState,
            initialLocalStateVector,
          );

        const oldSnapshot =
          this.yjs.snapshot(
            this.ydoc,
          );

        let update;

        if (
          usableInitialEvents.length >
          0
        ) {
          try {
            update =
              await this.updateFromEvents(
                usableInitialEvents,
              );
          } catch (error) {
            if (!this.destroyed) {
              console.error(
                "[YJS] Failed to construct initial Yjs update:",
                error,
              );
            }

            return;
          }

          if (
            update !== undefined &&
            !this.destroyed
          ) {
            this.yjs.applyUpdate(
              this.ydoc,
              update,
              this,
            );
          }
        }

        if (
          usableInitialEvents.length ===
            0 ||
          update === undefined
        ) {
          if (this.destroyed) {
            return;
          }

          const localUpdate =
            this.yjs.encodeStateAsUpdate(
              this.ydoc,
            );

          if (localUpdate.length > 2) {
            try {
              await this.publishUpdates([
                localUpdate,
              ]);
            } catch (error) {
              if (!this.destroyed) {
                console.error(
                  "[YJS] Failed to publish initial Yjs update:",
                  error,
                );
              }
            }
          }

          return;
        }

        if (this.destroyed) {
          return;
        }

        const remoteStateVector =
          this.yjs.encodeStateVectorFromUpdate(
            update,
          );

        const missingOnWire =
          this.yjs.diffUpdate(
            initialLocalState,
            remoteStateVector,
          );

        if (
          arrayBuffersAreEqual(
            deleteSetOnlyUpdate.buffer,
            missingOnWire.buffer,
          )
        ) {
          const serverDoc =
            new this.yjs.Doc();

          this.yjs.applyUpdate(
            serverDoc,
            update,
          );

          const serverSnapshot =
            this.yjs.snapshot(
              serverDoc,
            );

          snapshotContainsAllDeletes(
            serverSnapshot,
            oldSnapshot,
          );

          serverDoc.destroy();
        }

        if (
          missingOnWire.length > 2 &&
          !this.destroyed
        ) {
          try {
            await this.publishUpdates([
              missingOnWire,
            ]);
          } catch (error) {
            if (!this.destroyed) {
              console.error(
                "[YJS] Failed to publish missing Yjs update:",
                error,
              );
            }
          }
        }
      };

      /*
       * The creation event is the root of a room generation.
       *
       * A migration creates a new room by publishing a fresh creation
       * event containing a compact snapshot. Therefore the provider
       * must subscribe to the creation event itself, not just #e
       * updates referring to it.
       */
      const rootSubscription =
        this.ndk.subscribe(
          {
            kinds: [
              this.YJS_UPDATE_EVENT_KIND,
              NOSTR_ROOM_CONTROL_EVENT_KIND,
            ],
            ids: [
              this.nostrRoomCreateEventId,
            ],
          },
          {
            closeOnEose: false,
          },
        );

      /*
       * Normal incremental updates and deprecation controls point
       * back to the room creation event with an e tag.
       */
      const updateSubscription =
        this.ndk.subscribe(
          {
            kinds: [
              this.YJS_UPDATE_EVENT_KIND,
              NOSTR_ROOM_CONTROL_EVENT_KIND,
            ],
            "#e": [
              this.nostrRoomCreateEventId,
            ],
          },
          {
            closeOnEose: false,
          },
        );

      subscriptions.push(
        rootSubscription,
        updateSubscription,
      );

      this.subscription =
        subscriptions;

      for (const sub of subscriptions) {
        sub.on(
          "event",
          handleEvent,
        );

        sub.on(
          "events",
          handleEvents,
        );

        sub.on(
          "eose",
          handleEose,
        );
      }
    } catch (error) {
      if (!this.destroyed) {
        console.error(
          "[YJS] initialize() failed:",
          error,
        );
      }
    }
  }

  /* ------------------------------------------------------------------------ */
  /* Lifecycle                                                                */
  /* ------------------------------------------------------------------------ */

  destroy() {
    if (this.destroyed) {
      return;
    }

    this.destroyed = true;

    if (this.sendPendingTimeout) {
      clearTimeout(
        this.sendPendingTimeout,
      );

      this.sendPendingTimeout =
        undefined;
    }

    this.pendingUpdates = [];
    this.chunkBuffer.clear();

    try {
      this.ydoc.off(
        "update",
        this._documentUpdateListener,
      );
    } catch (error) {
      // Ignore.
    }

    try {
      for (const sub of this.subscription || []) {
        sub?.stop?.();
        sub?.close?.();
        sub?.unsubscribe?.();
      }
    } catch (error) {
      // Ignore.
    }

    this.subscription = undefined;
  }
}
