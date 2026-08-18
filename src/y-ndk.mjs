// plagiarized from:
// https://github.com/YousefED/nostr-crdt/blob/main/packages/nostr-crdt/src/createNostrCRDTRoom.ts
// NostrProvider with conservative D1/Nosflare-safe chunked updates.
//
// Based on:
// https://github.com/YousefED/nostr-crdt/blob/main/packages/nostr-crdt/src/createNostrCRDTRoom.ts
//
// The important constraint here is that a Nostr event contains more than
// just the Yjs binary. The binary is also base64 encoded and may be
// encrypted before being put into the event.
//
// Cloudflare D1 has a 2,000,000-byte maximum string/BLOB value, but SQL
// statements have a much smaller 100 KB limit. Nosflare also has to carry
// the complete Nostr event/message, so we intentionally use a much smaller
// payload.
//
// 32 KiB of raw Yjs data becomes roughly 43.7 KiB after base64 encoding,
// leaving substantial room for event JSON, tags, encryption overhead, etc.
//
// IMPORTANT:
// We never split an individual Yjs update by slicing its bytes.
// Yjs updates are structured binary data and arbitrary byte slicing would
// corrupt them.
const NOSTR_UPDATE_CHUNK_BYTES = 32 * 1024;

import { ObservableV2 } from "lib0/observable";
import { toBase64, fromBase64 } from "lib0/buffer";
import { NDKEvent } from "@nostr-dev-kit/ndk";
import {
  arrayBuffersAreEqual,
  snapshotContainsAllDeletes,
} from "./util.mjs";
import { finalizeEvent, verifyEvent } from "nostr-tools/pure";
import { SimplePool } from "nostr-tools/pool";

const pool = new SimplePool();

/**
 * Return the byte length of a Uint8Array, ArrayBuffer, or similar value.
 */
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

  throw new Error("Unable to determine binary update size");
}

/**
 * Convert a binary value to a Uint8Array.
 */
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

  return new Uint8Array(value);
}

/**
 * Split Yjs updates into conservative chunks.
 *
 * We deliberately do NOT split an individual Yjs update. A Yjs update is
 * structured data and cannot safely be divided at an arbitrary byte offset.
 *
 * The resulting chunks are merged Yjs updates and each chunk is kept below
 * NOSTR_UPDATE_CHUNK_BYTES based on the input update sizes.
 */
function splitUpdatesIntoChunks(
  yjs,
  updates,
  maxBytes = NOSTR_UPDATE_CHUNK_BYTES,
) {
  const chunks = [];

  let current = [];
  let currentSize = 0;

  for (const update of updates) {
    const size = getByteLength(update);

    if (size > maxBytes) {
      throw new Error(
        `A single Yjs update is ${size} bytes, which exceeds the ` +
          `${maxBytes} byte chunk limit. ` +
          `A single Yjs update cannot safely be split by slicing bytes.`,
      );
    }

    if (
      current.length > 0 &&
      currentSize + size > maxBytes
    ) {
      chunks.push(
        yjs.mergeUpdates(current),
      );

      current = [];
      currentSize = 0;
    }

    current.push(update);
    currentSize += size;
  }

  if (current.length > 0) {
    chunks.push(
      yjs.mergeUpdates(current),
    );
  }

  return chunks;
}

/**
 * Create the chunk tags shared by all chunks in a batch.
 */
function createChunkTag(batchId, index, total) {
  return [
    "chunk",
    batchId,
    String(index),
    String(total),
  ];
}

/**
 * Publish a signed or unsigned event.
 */
async function publishEvent({
  ndk,
  pool,
  explicitRelayUrls,
  secretNostrKey,
  eventTemplate,
}) {
  if (secretNostrKey === undefined) {
    const event = new NDKEvent(
      ndk,
      eventTemplate,
    );

    await event.publish();

    return event;
  }

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
    explicitRelayUrls,
    signedEvent,
  );

  return signedEvent;
}

/**
 * Create a Nostr CRDT room.
 *
 * The initial state is also chunked. The first chunk becomes the room
 * creation event, so its event ID remains the room ID used by the provider.
 *
 * Remaining initial-state chunks reference the first event with ["e", roomId].
 */
export async function createNostrCRDTRoom(params) {
  const {
    ndk,
    label,
    initialLocalState,
    YJS_UPDATE_EVENT_KIND,
    secretNostrKey,
    explicitRelayUrls,
    encrypt,
    yjs,
  } = {
    encrypt: (passthrough) => passthrough,
    ...params,
  };

  /**
   * If the caller did not provide yjs, preserve compatibility with the
   * original behavior and publish the initial state as one event.
   *
   * Normally createNostrCRDTRoom should receive the same yjs module that
   * NostrProvider uses.
   */
  if (!yjs) {
    return new Promise((resolve, reject) => {
      const sub = ndk.subscribe(
        {
          since:
            Math.floor(Date.now() / 1000) - 1,
          kinds: [
            YJS_UPDATE_EVENT_KIND,
          ],
        },
        {
          closeOnEose: true,
        },
      );

      let resolved = false;

      sub.on("event", (event) => {
        if (!resolved) {
          resolved = true;
          resolve(event.id);
        }
      });

      const publish = async () => {
        try {
          const event = await publishEvent({
            ndk,
            pool,
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
                encrypt(initialLocalState),
              ),
            },
          });

          if (!resolved && event?.id) {
            resolved = true;
            resolve(event.id);
          }
        } catch (error) {
          reject(error);
        }
      };

      publish();
    });
  }

  const initialChunks =
    splitUpdatesIntoChunks(
      yjs,
      [initialLocalState],
      NOSTR_UPDATE_CHUNK_BYTES,
    );

  /**
   * This normally produces one chunk. If the initial update itself is
   * larger than the limit, splitUpdatesIntoChunks intentionally throws
   * rather than corrupting the Yjs update.
   */
  const batchId = crypto.randomUUID();
  const total = initialChunks.length;

  return new Promise((resolve, reject) => {
    const sub = ndk.subscribe(
      {
        since:
          Math.floor(Date.now() / 1000) - 1,
        kinds: [
          YJS_UPDATE_EVENT_KIND,
        ],
      },
      {
        closeOnEose: true,
      },
    );

    let resolved = false;

    sub.on("event", (event) => {
      if (!resolved) {
        resolved = true;
        resolve(event.id);
      }
    });

    const publish = async () => {
      try {
        let roomId;

        /**
         * The first chunk is the room creation event.
         *
         * It intentionally does NOT contain an ["e", roomId] tag because
         * its own event ID is the room ID.
         */
        const firstChunk =
          initialChunks[0];

        const firstEvent =
          await publishEvent({
            ndk,
            pool,
            explicitRelayUrls,
            secretNostrKey,
            eventTemplate: {
              kind: YJS_UPDATE_EVENT_KIND,
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
                encrypt(firstChunk),
              ),
            },
          });

        roomId = firstEvent.id;

        /**
         * Publish remaining chunks after we know the room ID.
         */
        for (
          let i = 1;
          i < initialChunks.length;
          i++
        ) {
          const chunk =
            initialChunks[i];

          await publishEvent({
            ndk,
            pool,
            explicitRelayUrls,
            secretNostrKey,
            eventTemplate: {
              kind: YJS_UPDATE_EVENT_KIND,
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
                encrypt(chunk),
              ),
            },
          });
        }

        if (!resolved) {
          resolved = true;
          resolve(roomId);
        }
      } catch (error) {
        if (!resolved) {
          resolved = true;
          reject(error);
        }
      }
    };

    publish();
  });
}

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
      encrypt,
      decrypt,
    } = {
      encrypt: (passthrough) => passthrough,
      decrypt: (passthrough) => passthrough,
      ...params,
    };

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
      explicitRelayUrls;

    this.encrypt = encrypt;
    this.decrypt = decrypt;

    /**
     * batchId -> {
     *   total: number,
     *   chunks: Array<Uint8Array | undefined>,
     *   received: number
     * }
     */
    this.chunkBuffer = new Map();

    /**
     * Prevent an old/incomplete batch from living forever.
     */
    this.chunkBufferMaxAge = 10 * 60 * 1000;

    this.ydoc.on(
      "update",
      (update, origin) => {
        this.documentUpdateListener(
          update,
          origin,
        );
      },
    );
  }

  /**
   * Converts Nostr events into one merged Yjs update.
   *
   * Events passed here are expected to be either:
   *
   * 1. Legacy unchunked events.
   * 2. Complete chunk batches already reassembled by
   *    updateFromInitialEvents().
   */
  updateFromEvents(events) {
    const updates = events
      .map((event) => {
        try {
          return this.decrypt(
            fromBase64(event.content),
          );
        } catch (error) {
          console.error(
            "Failed to decode Nostr Yjs event:",
            error,
          );

          return undefined;
        }
      })
      .filter(Boolean);

    if (updates.length === 0) {
      return undefined;
    }

    return this.yjs.mergeUpdates(
      updates,
    );
  }

  /**
   * Publish a single update.
   */
  async publishUpdate(update) {
    return this.publishUpdates([
      update,
    ]);
  }

  /**
   * Publish one or more Yjs updates.
   *
   * Updates are grouped into conservative ~32 KiB raw binary chunks.
   *
   * Every batch receives:
   *
   *   ["chunk", batchId, "0", "3"]
   *   ["chunk", batchId, "1", "3"]
   *   ["chunk", batchId, "2", "3"]
   *
   * Every update event also references the room creation event using:
   *
   *   ["e", nostrRoomCreateEventId]
   */
  async publishUpdates(updates) {
    if (!updates || updates.length === 0) {
      return;
    }

    const chunks =
      splitUpdatesIntoChunks(
        this.yjs,
        updates,
        NOSTR_UPDATE_CHUNK_BYTES,
      );

    const batchId =
      crypto.randomUUID();

    const total = chunks.length;

    for (
      let i = 0;
      i < chunks.length;
      i++
    ) {
      const chunk = chunks[i];

      const encrypted =
        this.encrypt(chunk);

      const content =
        toBase64(encrypted);

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

      await publishEvent({
        ndk: this.ndk,
        pool,
        explicitRelayUrls:
          this.explicitRelayUrls,
        secretNostrKey:
          this.secretNostrKey,
        eventTemplate: {
          kind:
            this.YJS_UPDATE_EVENT_KIND,
          created_at:
            Math.floor(Date.now() / 1000),
          tags,
          content,
        },
      });
    }
  }

  pendingUpdates = [];
  sendPendingTimeout = undefined;

  async documentUpdateListener(
    update,
    origin,
  ) {
    /**
     * Do not rebroadcast updates that originated from this provider.
     */
    if (origin === this) {
      return;
    }

    /**
     * Do not rebroadcast updates from another provider.
     */
    if (origin?.provider) {
      return;
    }

    this.pendingUpdates.push(update);

    if (this.sendPendingTimeout) {
      clearTimeout(
        this.sendPendingTimeout,
      );
    }

    this.sendPendingTimeout =
      setTimeout(() => {
        const updates =
          this.pendingUpdates;

        this.pendingUpdates = [];

        this.sendPendingTimeout =
          undefined;

        this.publishUpdates(updates)
          .catch((error) => {
            console.error(
              "Failed to publish Yjs update:",
              error,
            );

            /**
             * Requeue the updates so they aren't silently lost.
             */
            this.pendingUpdates.unshift(
              ...updates,
            );
          });
      }, 100);
  }

  /**
   * Remove stale incomplete chunk batches.
   */
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

  /**
   * Process one incoming Nostr event.
   */
  processIncomingEvent = (event) => {
    const chunkTag =
      event.tags?.find(
        (tag) => tag[0] === "chunk",
      );

    /**
     * Backwards compatibility:
     *
     * Old events do not contain chunk metadata.
     */
    if (!chunkTag) {
      try {
        const update =
          this.decrypt(
            fromBase64(event.content),
          );

        if (!update) {
          return;
        }

        this.yjs.applyUpdate(
          this.ydoc,
          update,
          this,
        );
      } catch (error) {
        console.error(
          "Failed to process incoming Yjs event:",
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
        "Ignoring invalid Nostr Yjs chunk:",
        chunkTag,
      );

      return;
    }

    this.cleanupChunkBuffer();

    let batch =
      this.chunkBuffer.get(batchId);

    /**
     * If this is the first chunk we have seen,
     * create the batch buffer.
     */
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

    /**
     * Protect against malformed events where different chunks
     * claim different totals.
     */
    if (batch.total !== total) {
      console.warn(
        "Ignoring chunk with mismatched total:",
        chunkTag,
      );

      return;
    }

    /**
     * Duplicate chunk/event.
     */
    if (
      batch.chunks[index] !==
      undefined
    ) {
      return;
    }

    let update;

    try {
      update = this.decrypt(
        fromBase64(event.content),
      );
    } catch (error) {
      console.error(
        "Failed to decode incoming Yjs chunk:",
        error,
      );

      return;
    }

    if (!update) {
      return;
    }

    batch.chunks[index] = update;
    batch.received++;

    /**
     * Wait until every chunk has arrived.
     */
    if (
      batch.received !== batch.total
    ) {
      return;
    }

    try {
      /**
       * All chunks are available.
       *
       * mergeUpdates() reconstructs one valid Yjs update.
       */
      const mergedUpdate =
        this.yjs.mergeUpdates(
          batch.chunks,
        );

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
        "Failed to reassemble Yjs chunk batch:",
        error,
      );

      /**
       * Remove the broken batch rather than leaving it permanently
       * marked as complete.
       */
      this.chunkBuffer.delete(
        batchId,
      );
    }
  };

  /**
   * Process multiple incoming Nostr events.
   */
  processIncomingEvents = (events) => {
    for (const event of events) {
      this.processIncomingEvent(
        event,
      );
    }
  };

  /**
   * Reassemble complete chunk batches from the initial event history.
   *
   * Legacy events are returned immediately.
   *
   * Incomplete chunk batches are omitted because the live subscription
   * will continue receiving events after EOSE.
   */
  updateFromInitialEvents(events) {
    const completeEvents = [];
    const batches = new Map();

    for (const event of events) {
      const chunkTag =
        event.tags?.find(
          (tag) => tag[0] === "chunk",
        );

      /**
       * Legacy unchunked event.
       */
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
        batches.get(batchId);

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

      /**
       * Ignore malformed batches whose total changes.
       */
      if (batch.total !== total) {
        continue;
      }

      /**
       * Ignore duplicate events.
       */
      if (
        batch.events[index] !==
        undefined
      ) {
        continue;
      }

      batch.events[index] = event;
      batch.received++;
    }

    /**
     * Only use complete batches.
     *
     * The event order is reconstructed using the chunk index rather
     * than relying on relay delivery order.
     */
    for (
      const batch of batches.values()
    ) {
      if (
        batch.received !==
        batch.total
      ) {
        continue;
      }

      completeEvents.push(
        ...batch.events,
      );
    }

    return completeEvents;
  }

  async initialize() {
    try {
      let eoseSeen = false;
      const initialEvents = [];

      const sub =
        this.ndk.subscribe(
          {
            kinds: [
              this.YJS_UPDATE_EVENT_KIND,
            ],
            since: 0,
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
            this.processIncomingEvent(
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
        () => {
          eoseSeen = true;

          /**
           * Reassemble complete historical chunk batches.
           */
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

          /**
           * Apply remote history.
           */
          if (
            usableInitialEvents.length >
            0
          ) {
            update =
              this.updateFromEvents(
                usableInitialEvents,
              );

            if (update !== undefined) {
              this.yjs.applyUpdate(
                this.ydoc,
                update,
                this,
              );
            }
          }

          /**
           * No remote history exists.
           *
           * Publish the local document, using the same conservative
           * chunking path as normal updates.
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
              localUpdate.length > 2
            ) {
              this.publishUpdates([
                localUpdate,
              ]).catch((error) => {
                console.error(
                  "Failed to publish initial Yjs update:",
                  error,
                );
              });
            }

            return;
          }

          /**
           * Find local changes that aren't on the server.
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

          /**
           * missingOnWire can contain the entire delete set on startup.
           *
           * diffUpdate() doesn't handle deletes in the same way as normal
           * content changes, so retain the original snapshot check.
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

            if (
              snapshotContainsAllDeletes(
                serverSnapshot,
                oldSnapshot,
              )
            ) {
              /**
               * missingOnWire contains only deletes that are already
               * represented by the server state.
               */
            }
          }

          /**
           * publishUpdates() performs the D1/Nosflare-safe chunking.
           */
          if (
            missingOnWire.length > 2
          ) {
            this.publishUpdates([
              missingOnWire,
            ]).catch((error) => {
              console.error(
                "Failed to publish missing Yjs update:",
                error,
              );
            });
          }
        },
      );
    } catch (error) {
      console.error(error);
    }
  }
}
