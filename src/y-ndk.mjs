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

const NOSTR_UPDATE_CHUNK_BYTES = 32 * 1024;

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

/*
 * Encryption remains completely controlled by the encrypt() callback.
 *
 * The callback returns:
 *
 *   {
 *     data: Uint8Array,
 *     encrypted: boolean
 *   }
 *
 * The provider does not know how encryption works.
 */
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
   * Encryption/decryption is owned entirely by the callback supplied
   * by the caller.
   *
   * For plaintext events, there is nothing to decrypt.
   */
  if (!encrypted) {
    return toUint8Array(input);
  }

  if (typeof decrypt !== "function") {
    throw new Error(
      "[YJS] Received encrypted event but no decrypt() function is configured",
    );
  }

  /*
   * IMPORTANT:
   *
   * Do not pass identities, recipients, keys, configuration, or context.
   *
   * The callback is responsible for all of that through its closure.
   */
  const result = await decrypt(input);

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

  const batchId = crypto.randomUUID();
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

      decrypt = async (value) => value,
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

    this.encrypt = encrypt;
    this.decrypt = decrypt;

    this.chunkBuffer = new Map();
    this.chunkBufferMaxAge = 10 * 60 * 1000;

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

    if (!this.nostrRoomCreateEventId) {
      console.warn(
        "[YJS] NostrProvider created without nostrRoomCreateEventId",
      );
    }
  }

  /* ------------------------------------------------------------------------ */
  /* Decode events                                                            */
  /* ------------------------------------------------------------------------ */

  async decodeEvent(event) {
    const encoded = fromBase64(event.content);

    const encrypted =
      hasAgeEncryptionTag(event);

    console.log(
      "[YJS] Decoding event",
      {
        id: event.id,
        encrypted,
        contentBytes: encoded.byteLength,
        tags: event.tags,
      },
    );

    const update = await runDecrypt(
      this.decrypt,
      encoded,
      encrypted,
    );

    console.log(
      "[YJS] Decoded event",
      {
        id: event.id,
        encrypted,
        updateBytes: update.byteLength,
        firstBytes: Array.from(
          update.slice(0, 16),
        ),
      },
    );

    return update;
  }

  async updateFromEvents(events) {
    const updates = [];

    for (const event of events) {
      try {
        const update =
          await this.decodeEvent(event);

        if (update.byteLength === 0) {
          console.warn(
            "[YJS] Ignoring empty decrypted update",
          );
          continue;
        }

        updates.push(update);
      } catch (error) {
        console.error(
          "[YJS] Failed to decode/decrypt event:",
          {
            eventId: event?.id,
            error,
          },
        );
      }
    }

    if (updates.length === 0) {
      return undefined;
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

    const batchId = crypto.randomUUID();
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

      console.log(
        "[YJS] Publishing chunk",
        {
          batchId,
          index: i,
          total,
          encrypted: encrypted.encrypted,
          rawBytes: chunk.byteLength,
          encryptedBytes:
            encrypted.data.byteLength,
          base64Bytes: content.length,
        },
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

    this.pendingUpdates.push(
      toUint8Array(update),
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
  /* Chunk cleanup                                                            */
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

    const chunkTag =
      event.tags?.find(
        (tag) =>
          tag[0] === "chunk",
      );

    if (!chunkTag) {
      try {
        const update =
          await this.decodeEvent(event);

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
      console.warn(
        "[YJS] Ignoring invalid chunk:",
        chunkTag,
      );
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

    if (
      batch.chunks[index] !==
      undefined
    ) {
      return;
    }

    try {
      const update =
        await this.decodeEvent(event);

      if (update.byteLength === 0) {
        return;
      }

      batch.chunks[index] = update;
      batch.received++;
    } catch (error) {
      console.error(
        "[YJS] Failed to decode/decrypt incoming chunk:",
        {
          eventId: event?.id,
          error,
        },
      );
      return;
    }

    if (
      batch.received !==
      batch.total
    ) {
      return;
    }

    if (
      batch.chunks.some(
        (chunk) =>
          chunk === undefined,
      )
    ) {
      return;
    }

    try {
      console.log(
        "[YJS] COMPLETE CHUNK BATCH",
        {
          batchId,
          total: batch.total,
          received: batch.received,
          sizes: batch.chunks.map(
            (chunk) =>
              chunk?.byteLength,
          ),
        },
      );

      const mergedUpdate =
        this.yjs.mergeUpdates(
          batch.chunks,
        );

      if (
        !mergedUpdate ||
        mergedUpdate.byteLength === 0
      ) {
        throw new Error(
          "Yjs mergeUpdates() returned an empty update",
        );
      }

      this.chunkBuffer.delete(
        batchId,
      );

      this.yjs.applyUpdate(
        this.ydoc,
        mergedUpdate,
        this,
      );
    } catch (error) {
      console.error(
        "[YJS] Failed to reassemble Yjs chunk batch:",
        {
          batchId,
          error,
        },
      );

      this.chunkBuffer.delete(
        batchId,
      );
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
      let eoseSeen = false;
      const initialEvents = [];

      const sub =
        this.ndk.subscribe(
          {
            kinds: [
              this.YJS_UPDATE_EVENT_KIND,
            ],
            "#e": [
              this.nostrRoomCreateEventId,
            ],
          },
          {
            closeOnEose: false,
          },
        );

      this.subscription = sub;

      sub.on(
        "event",
        (event) => {
          if (this.destroyed) {
            return;
          }

          if (!eoseSeen) {
            initialEvents.push(event);
          } else {
            void this.processIncomingEvent(
              event,
            );
          }
        },
      );

      sub.on(
        "events",
        (events) => {
          if (
            this.destroyed ||
            !eoseSeen
          ) {
            return;
          }

          this.processIncomingEvents(
            events,
          );
        },
      );

      sub.on(
        "eose",
        async () => {
          if (this.destroyed) {
            return;
          }

          eoseSeen = true;

          const usableInitialEvents =
            this.updateFromInitialEvents(
              initialEvents,
            );

          console.log(
            "[YJS] Initial events",
            {
              received:
                initialEvents.length,
              usable:
                usableInitialEvents.length,
            },
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
        },
      );
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
      console.warn(
        "[YJS] Failed to remove Y.Doc listener:",
        error,
      );
    }

    try {
      this.subscription?.stop?.();
      this.subscription?.close?.();
      this.subscription?.unsubscribe?.();
    } catch (error) {
      console.warn(
        "[YJS] Failed to close Nostr subscription:",
        error,
      );
    }

    this.subscription = undefined;
  }
}
