// y-ndk.mjs

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

/* -------------------------------------------------------------------------- */
/* Binary helpers                                                             */
/* -------------------------------------------------------------------------- */

function getByteLength(value) {
  if (value == null) {
    return 0;
  }

  if (typeof value.byteLength === "number") {
    return value.byteLength;
  }

  if (typeof value.length === "number") {
    return value.length;
  }

  throw new Error(
    "Unable to determine binary update size",
  );
}

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

  if (value instanceof Promise) {
    throw new Error(
      "Encryption/decryption returned a Promise. " +
        "The provider must await it before converting to Uint8Array.",
    );
  }

  return new Uint8Array(value);
}

function normalizeDecryptedValue(value) {
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

  return toUint8Array(value);
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
          `${maxBytes} bytes. ` +
          `A single Yjs update cannot safely be split by slicing bytes.`,
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

function createChunkTag(
  batchId,
  index,
  total,
) {
  return [
    "chunk",
    batchId,
    String(index),
    String(total),
  ];
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

  /*
   * Manual signing.
   */
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

  /*
   * NDK signing.
   */
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
    encrypt = async (value) => value,
    yjs,
  } = params;

  /*
   * Legacy mode.
   */
  if (!yjs) {
    const encrypted = await encrypt(
      toUint8Array(initialLocalState),
    );

    const event = await publishEvent({
      ndk,
      explicitRelayUrls,
      secretNostrKey,
      eventTemplate: {
        kind: YJS_UPDATE_EVENT_KIND,
        created_at:
          Math.floor(Date.now() / 1000),
        tags: [
          ["crdt", label],
        ],
        content: toBase64(
          toUint8Array(encrypted),
        ),
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

  const batchId =
    crypto.randomUUID();

  const total =
    initialChunks.length;

  /*
   * First chunk creates the room.
   */
  const encryptedFirst =
    await encrypt(
      initialChunks[0],
    );

  const firstEvent =
    await publishEvent({
      ndk,
      explicitRelayUrls,
      secretNostrKey,
      eventTemplate: {
        kind:
          YJS_UPDATE_EVENT_KIND,
        created_at:
          Math.floor(Date.now() / 1000),
        tags: [
          ["crdt", label],
          createChunkTag(
            batchId,
            0,
            total,
          ),
        ],
        content: toBase64(
          toUint8Array(
            encryptedFirst,
          ),
        ),
      },
    });

  const roomId =
    firstEvent.id;

  if (!roomId) {
    throw new Error(
      "Nostr room creation event did not have an event ID",
    );
  }

  /*
   * Remaining initial chunks reference roomId.
   */
  for (
    let i = 1;
    i < initialChunks.length;
    i++
  ) {
    const encrypted =
      await encrypt(
        initialChunks[i],
      );

    await publishEvent({
      ndk,
      explicitRelayUrls,
      secretNostrKey,
      eventTemplate: {
        kind:
          YJS_UPDATE_EVENT_KIND,
        created_at:
          Math.floor(Date.now() / 1000),
        tags: [
          ["e", roomId],
          createChunkTag(
            batchId,
            i,
            total,
          ),
        ],
        content: toBase64(
          toUint8Array(encrypted),
        ),
      },
    });
  }

  return roomId;
}

/* -------------------------------------------------------------------------- */
/* NostrProvider                                                              */
/* -------------------------------------------------------------------------- */

export class NostrProvider
  extends ObservableV2 {
  constructor(params) {
    const {
      yjs,
      ydoc,
      nostrRoomCreateEventId,
      ndk,
      YJS_UPDATE_EVENT_KIND,
      secretNostrKey,
      explicitRelayUrls,
      encrypt = async (value) => value,
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

    this.chunkBufferMaxAge =
      10 * 60 * 1000;

    this.pendingUpdates = [];
    this.sendPendingTimeout =
      undefined;

    if (
      !this.nostrRoomCreateEventId
    ) {
      console.warn(
        "[YJS] NostrProvider created without nostrRoomCreateEventId",
      );
    }

    this.ydoc.on(
      "update",
      (update, origin) => {
        void this.documentUpdateListener(
          update,
          origin,
        );
      },
    );
  }

  /* ------------------------------------------------------------------------ */
  /* Decode events                                                            */
  /* ------------------------------------------------------------------------ */

  async updateFromEvents(events) {
    const updates = [];

    for (const event of events) {
      try {
        const encoded =
          fromBase64(
            event.content,
          );

        const decrypted =
          await this.decrypt(
            encoded,
          );

        const update =
          normalizeDecryptedValue(
            decrypted,
          );

        if (
          update.byteLength === 0
        ) {
          console.warn(
            "[YJS] Ignoring empty decrypted update",
          );
          continue;
        }

        updates.push(update);
      } catch (error) {
        console.error(
          "[YJS] Failed to decode/decrypt event:",
          error,
        );
      }
    }

    if (updates.length === 0) {
      return undefined;
    }

    return toUint8Array(
      this.yjs.mergeUpdates(
        updates,
      ),
    );
  }

  /* ------------------------------------------------------------------------ */
  /* Publish                                                                  */
  /* ------------------------------------------------------------------------ */

  async publishUpdate(update) {
    return this.publishUpdates([
      update,
    ]);
  }

  async publishUpdates(updates) {
    if (
      !updates ||
      updates.length === 0
    ) {
      return;
    }

    if (
      !this.nostrRoomCreateEventId
    ) {
      throw new Error(
        "[YJS] Cannot publish update: " +
          "nostrRoomCreateEventId is undefined",
      );
    }

    const chunks =
      splitUpdatesIntoChunks(
        this.yjs,
        updates,
        NOSTR_UPDATE_CHUNK_BYTES,
      );

    const batchId =
      crypto.randomUUID();

    const total =
      chunks.length;

    for (
      let i = 0;
      i < chunks.length;
      i++
    ) {
      const chunk =
        chunks[i];

      if (
        !(chunk instanceof Uint8Array)
      ) {
        throw new Error(
          "[YJS] Chunk is not Uint8Array",
        );
      }

      if (
        chunk.byteLength === 0
      ) {
        console.warn(
          "[YJS] Refusing to publish empty Yjs chunk",
        );
        continue;
      }

      /*
       * Encryption is asynchronous.
       */
      const encrypted =
        await this.encrypt(
          chunk,
        );

      if (
        encrypted == null
      ) {
        throw new Error(
          "[YJS] encrypt() returned null/undefined",
        );
      }

      const encryptedBytes =
        toUint8Array(
          encrypted,
        );

      if (
        encryptedBytes.byteLength ===
        0
      ) {
        throw new Error(
          "[YJS] Encryption produced empty data",
        );
      }

      const content =
        toBase64(
          encryptedBytes,
        );

      if (!content) {
        throw new Error(
          "[YJS] Base64 encoded content is empty",
        );
      }

      const tags = [
        [
          "e",
          this.nostrRoomCreateEventId,
        ],
        createChunkTag(
          batchId,
          i,
          total,
        ),
      ];

      console.log(
        "[YJS] Publishing chunk",
        {
          batchId,
          index: i,
          total,
          rawBytes:
            chunk.byteLength,
          encryptedBytes:
            encryptedBytes.byteLength,
          base64Bytes:
            content.length,
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
    /*
     * Remote Yjs changes must not be
     * rebroadcast.
     */
    if (origin === this) {
      return;
    }

    if (origin?.provider) {
      return;
    }

    this.pendingUpdates.push(
      toUint8Array(update),
    );

    if (
      this.sendPendingTimeout
    ) {
      clearTimeout(
        this.sendPendingTimeout,
      );
    }

    this.sendPendingTimeout =
      setTimeout(
        async () => {
          const updates =
            this.pendingUpdates;

          this.pendingUpdates =
            [];

          this.sendPendingTimeout =
            undefined;

          try {
            await this.publishUpdates(
              updates,
            );
          } catch (error) {
            console.error(
              "Failed to publish Yjs update:",
              error,
            );

            /*
             * Don't lose updates.
             */
            this.pendingUpdates.unshift(
              ...updates,
            );
          }
        },
        100,
      );
  }

  /* ------------------------------------------------------------------------ */
  /* Chunk cleanup                                                            */
  /* ------------------------------------------------------------------------ */

  cleanupChunkBuffer() {
    const now =
      Date.now();

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

  async processIncomingEvent(
    event,
  ) {
    const chunkTag =
      event.tags?.find(
        (tag) =>
          tag[0] === "chunk",
      );

    /*
     * Legacy event.
     */
    if (!chunkTag) {
      try {
        const encoded =
          fromBase64(
            event.content,
          );

        const decrypted =
          await this.decrypt(
            encoded,
          );

        const update =
          normalizeDecryptedValue(
            decrypted,
          );

        if (
          update.byteLength === 0
        ) {
          console.warn(
            "[YJS] Ignoring empty legacy update",
          );
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
          error,
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

    const index =
      Number(indexString);

    const total =
      Number(totalString);

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
      this.chunkBuffer.get(
        batchId,
      );

    if (!batch) {
      batch = {
        total,
        chunks:
          new Array(total),
        received: 0,
        createdAt:
          Date.now(),
      };

      this.chunkBuffer.set(
        batchId,
        batch,
      );
    }

    if (
      batch.total !== total
    ) {
      console.warn(
        "[YJS] Chunk total mismatch:",
        {
          batchId,
          expected:
            batch.total,
          received:
            total,
        },
      );

      return;
    }

    if (
      batch.chunks[index] !==
      undefined
    ) {
      return;
    }

    try {
      const encoded =
        fromBase64(
          event.content,
        );

      const decrypted =
        await this.decrypt(
          encoded,
        );

      const update =
        normalizeDecryptedValue(
          decrypted,
        );

      if (
        update.byteLength === 0
      ) {
        console.warn(
          "[YJS] Ignoring empty chunk",
          chunkTag,
        );
        return;
      }

      batch.chunks[index] =
        update;

      batch.received++;
    } catch (error) {
      console.error(
        "[YJS] Failed to decode/decrypt incoming chunk:",
        error,
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
      console.error(
        "[YJS] Batch is complete but contains missing chunks",
        {
          batchId,
          total:
            batch.total,
          received:
            batch.received,
        },
      );

      return;
    }

    try {
      console.log(
        "[YJS] COMPLETE CHUNK BATCH",
        {
          batchId,
          total:
            batch.total,
          received:
            batch.received,
          sizes:
            batch.chunks.map(
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
        mergedUpdate.byteLength ===
          0
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
        error,
      );

      this.chunkBuffer.delete(
        batchId,
      );
    }
  }

  processIncomingEvents(
    events,
  ) {
    for (const event of events) {
      void this.processIncomingEvent(
        event,
      );
    }
  }

  /* ------------------------------------------------------------------------ */
  /* Initial history                                                          */
  /* ------------------------------------------------------------------------ */

  updateFromInitialEvents(
    events,
  ) {
    const completeEvents = [];
    const batches = new Map();

    for (const event of events) {
      const chunkTag =
        event.tags?.find(
          (tag) =>
            tag[0] === "chunk",
        );

      /*
       * Legacy event.
       */
      if (!chunkTag) {
        completeEvents.push(
          event,
        );
        continue;
      }

      const [
        ,
        batchId,
        indexString,
        totalString,
      ] = chunkTag;

      const index =
        Number(indexString);

      const total =
        Number(totalString);

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

      let batch =
        batches.get(
          batchId,
        );

      if (!batch) {
        batch = {
          total,
          events:
            new Array(total),
          received: 0,
        };

        batches.set(
          batchId,
          batch,
        );
      }

      if (
        batch.total !== total
      ) {
        continue;
      }

      if (
        batch.events[index] !==
        undefined
      ) {
        continue;
      }

      batch.events[index] =
        event;

      batch.received++;
    }

    for (
      const batch of
        batches.values()
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
      !this.nostrRoomCreateEventId
    ) {
      console.error(
        "[YJS] Cannot initialize provider: " +
          "nostrRoomCreateEventId is undefined",
      );

      return;
    }

    try {
      let eoseSeen = false;

      const initialEvents =
        [];

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

      sub.on(
        "event",
        (event) => {
          if (!eoseSeen) {
            initialEvents.push(
              event,
            );
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
          if (eoseSeen) {
            this.processIncomingEvents(
              events,
            );
          }
        },
      );

      sub.on(
        "eose",
        async () => {
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

          /*
           * Apply remote history.
           */
          if (
            usableInitialEvents.length >
            0
          ) {
            update =
              await this.updateFromEvents(
                usableInitialEvents,
              );

            if (
              update !==
              undefined
            ) {
              this.yjs.applyUpdate(
                this.ydoc,
                update,
                this,
              );
            }
          }

          /*
           * No remote state.
           */
          if (
            usableInitialEvents.length ===
              0 ||
            update === undefined
          ) {
            const localUpdate =
              this.yjs.encodeStateAsUpdate(
                this.ydoc,
              );

            if (
              localUpdate.length >
              2
            ) {
              try {
                await this.publishUpdates(
                  [localUpdate],
                );
              } catch (error) {
                console.error(
                  "[YJS] Failed to publish initial Yjs update:",
                  error,
                );
              }
            }

            return;
          }

          /*
           * Find local state missing
           * from remote state.
           */
          const remoteStateVector =
            this.yjs.encodeStateVectorFromUpdate(
              update,
            );

          const missingOnWire =
            this.yjs.diffUpdate(
              initialLocalState,
              remoteStateVector,
            );

          /*
           * Preserve delete-set check.
           */
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
          }

          /*
           * Publish local changes
           * not present remotely.
           */
          if (
            missingOnWire.length >
            2
          ) {
            try {
              await this.publishUpdates(
                [missingOnWire],
              );
            } catch (error) {
              console.error(
                "[YJS] Failed to publish missing Yjs update:",
                error,
              );
            }
          }
        },
      );
    } catch (error) {
      console.error(
        "[YJS] initialize() failed:",
        error,
      );
    }
  }
}
