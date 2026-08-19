Log in
Sign up for free
You said:

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
      console.log("[YJS] COMPLETE CHUNK BATCH", {
        batchId,
        total: batch.total,
        received: batch.received,
      });
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
          },
          {
            closeOnEose: false,
          },
        );

      sub.on(
        "event",
        (event) => {
          console.log("NOSTR EVENT RECEIVED", {
            id: event.id,
            kind: event.kind,
            tags: event.tags,
            contentLength: event.content?.length,
          });
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
rssposts.tsx:569 Failed to publish Yjs update: Error: can't serialize event with wrong or missing properties
    at serializeEvent (@ashby-shoal_y-ndk.js?v=d427d940:5960:11)
    at getEventHash3 (@ashby-shoal_y-ndk.js?v=d427d940:5964:45)
    at finalizeEvent (@ashby-shoal_y-ndk.js?v=d427d940:5935:16)
    at publishEvent (@ashby-shoal_y-ndk.js?v=d427d940:7158:23)
    at NostrProvider.publishUpdates (@ashby-shoal_y-ndk.js?v=d427d940:7572:13)
    at @ashby-shoal_y-ndk.js?v=d427d940:7603:12

ChatGPT said:
The failure is happening before anything is sent to the relay. The stack trace points directly at:

finalizeEvent(eventTemplate, secretNostrKey) → getEventHash() → serializeEvent()

nostr-tools requires the event to have:

kind: number
created_at: number
tags: array of string arrays
content: string
and, by the time serializeEvent() runs, pubkey: a 64-character lowercase hex string.
U
UNPKG
+1
Your event template itself looks valid. The suspicious value is therefore secretNostrKey.

Most likely cause
finalizeEvent() expects the secret key as a Uint8Array, not a hex string or nsec... string.
N
npm
+1

So if secretNostrKey is something like:

"nsec1..."


or:

"0123456789abcdef..."


then the signing path can fail in confusing ways.

If you're storing the private key as hex, convert it first:

import { hexToBytes } from "@noble/hashes/utils";

const secretKeyBytes =
  typeof secretNostrKey === "string"
    ? hexToBytes(secretNostrKey)
    : secretNostrKey;


Then:

const signedEvent = finalizeEvent(
  eventTemplate,
  secretKeyBytes,
);


Add this diagnostic immediately
I'd change your publishEvent() temporarily to:

const signedEvent = finalizeEvent(
  eventTemplate,
  secretNostrKey,
);


and before it:

console.log("Nostr event template:", {
  kind: eventTemplate.kind,
  kindType: typeof eventTemplate.kind,

  created_at: eventTemplate.created_at,
  createdAtType: typeof eventTemplate.created_at,

  tags: eventTemplate.tags,
  tagsAreArray: Array.isArray(eventTemplate.tags),

  contentType: typeof eventTemplate.content,
  contentLength: eventTemplate.content?.length,

  secretKeyType:
    secretNostrKey?.constructor?.name,
  secretKeyLength:
    secretNostrKey?.length,
});


If you're using the expected key format, you should see something approximately like:

kindType: "number"
createdAtType: "number"
tagsAreArray: true
contentType: "string"
secretKeyType: "Uint8Array"
secretKeyLength: 32


There is another issue worth fixing
Your publishEvent() has two completely different event implementations:

if (secretNostrKey === undefined) {
  const event = new NDKEvent(
    ndk,
    eventTemplate,
  );

  await event.publish();

  return event;
}


versus:

const signedEvent = finalizeEvent(
  eventTemplate,
  secretNostrKey,
);

await pool.publish(
  explicitRelayUrls,
  signedEvent,
);


That means the chunking code works through NDK when there is no key, but switches to raw nostr-tools when there is a key.

I'd make the signed branch validate the inputs explicitly:

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

  if (
    !(secretNostrKey instanceof Uint8Array) ||
    secretNostrKey.length !== 32
  ) {
    throw new Error(
      "secretNostrKey must be a 32-byte Uint8Array",
    );
  }

  if (typeof eventTemplate.kind !== "number") {
    throw new Error(
      `Invalid Nostr event kind: ${eventTemplate.kind}`,
    );
  }

  if (
    typeof eventTemplate.created_at !==
    "number"
  ) {
    throw new Error(
      "Invalid Nostr created_at",
    );
  }

  if (
    !Array.isArray(eventTemplate.tags) ||
    eventTemplate.tags.some(
      (tag) =>
        !Array.isArray(tag) ||
        tag.some(
          (value) =>
            typeof value !== "string",
        ),
    )
  ) {
    throw new Error(
      "Invalid Nostr tags",
    );
  }

  if (
    typeof eventTemplate.content !==
    "string"
  ) {
    throw new Error(
      "Invalid Nostr content",
    );
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


One more thing I'd check
Your YJS_UPDATE_EVENT_KIND could also be the culprit if it's coming from configuration as a string:

YJS_UPDATE_EVENT_KIND = "30078"


rather than:

YJS_UPDATE_EVENT_KIND = 30078


nostr-tools specifically validates kind as a number.
U
UNPKG

So this:

kind:
  this.YJS_UPDATE_EVENT_KIND,


needs to produce a number.

You can make that bulletproof at the call site:

kind: Number(
  this.YJS_UPDATE_EVENT_KIND,
),


provided you actually want to accept numeric strings.

My first bet, though, is secretNostrKey format/type. The event template shown in your code satisfies the normal finalizeEvent() shape; the error occurs when serializeEvent() is trying to validate the event after finalizeEvent() adds the public key.
U
UNPKG

Also, your 32 KiB chunking approach is unrelated to this particular error—the exception is occurring during event signing, before pool.publish() is reached.


U
N
Sources


You said:

import {
  For,
  createEffect,
  createSignal,
  createResource,
  Show,
  createMemo
} from "solid-js";
import * as yjs from "yjs";
import i18n from "../../i18n";
import { useParams } from "@solidjs/router";
import { useLocale } from "@kobalte/core/i18n";
import NDKCacheAdapterDexie from "@nostr-dev-kit/ndk-cache-dexie";
import { IndexeddbPersistence } from "y-indexeddb";
import WinkClassifier from "wink-naive-bayes-text-classifier";
import { LN, SATS } from "@getalby/sdk";
import {
  fetchRssPosts,
  parsePosts,
  similarity,
  prepNLPTask,
  scoreRSSPosts,
  removeEmpties,
} from "../../util";
import NDK, { NDKNip07Signer, NDKPrivateKeySigner } from "@nostr-dev-kit/ndk";
import { NostrProvider } from "@ashby-shoal/y-ndk";
import { nip19 } from "nostr-tools";
import { Encrypter, Decrypter, armor } from "age-encryption";
import { useNostrKeys } from "../nostrkeys/NostrKeysContext";
import { useChannels } from "../channels/ChannelsContext";
import { useRssfeeds } from "../rssfeeds/RssfeedsContext";
import { useCorsproxies } from "../corsproxies/CorsproxiesContext";
import { useNostrRelays } from "../nostrrelays/NostrRelaysContext";
import { useSubscribers } from "../subscribers/SubscribersContext";
import { useConnections } from "../connections/ConnectionsContext";
import { useTrainlabels } from "../trainlabels/TrainlabelsContext";
import { Checkbox } from "../../components/Checkbox";
import { SkeletonPost } from "../../components/SkeletonPost";
import PostDisplay from "./PostDisplay";
import PostTrain from "./PostTrain";
import { makePersisted } from "@solid-primitives/storage";
import { isServer } from "solid-js/web";
import localforage from "localforage";
import Header from "../../components/Header";
import Nav from "../../components/Nav";
import { SectionHeader } from "../../components/SectionHeader";
import { TrainlabelType } from "../trainlabels/trainlabel";
import { RssfeedType } from "../rssfeeds/rssfeed";
import { Button } from "../../components/Button";

export default function RssPosts() {
  const params = useParams();
  const { locale } = useLocale();
  const [subscribers, {}] = useSubscribers();
  const [nostrRelays, {}] = useNostrRelays();
  const [connections, {}] = useConnections();
  const [nostrKeys, {}] = useNostrKeys();
  const [channels, {}] = useChannels();
  const [rssfeeds, {}] = useRssfeeds();
  const [trainlabels, {}] = useTrainlabels();
  const [corsproxies, {}] = useCorsproxies();
  const nostrCrdtEventKind = 7777;

  const [hideProcessedPosts, setHideProcessedPosts, initHideProcessedPosts] = makePersisted(
    createSignal(true),
    {
      name: `hideProcessed-${params.trainlabel}`,
      storage: !isServer ? localforage : undefined,
    },
  );
  createResource(() => initHideProcessedPosts)[0]();

  const [trainMode, setTrainMode, initTrainMode] = makePersisted(
    createSignal(false),
    {
      name: `trainMode-${params.trainlabel}`,
      storage: !isServer ? localforage : undefined,
    }
  )

  createResource(() => initTrainMode)[0]();

  const [hideURL, setHideURL, initHideURL] = makePersisted(
    createSignal(true),
    {
      name: `hideURL-${params.trainlabel}`,
      storage: !isServer ? localforage : undefined,
    }
  )

  createResource(() => initHideURL)[0]();

  const rssFeedsForTrainLabel = () => {
    const theTimeRightNow = Date.now();
    const trainLabel = trainlabels().find((trainlabel: TrainlabelType) => {
      return trainlabel.label === params.trainlabel;
    });
    return rssfeeds()
      .filter((rssfeed) => rssfeed.disabled !== true)
      .filter((rssfeed) => {
        if (rssfeed.disableUntil || -1 === -1) {
          return true;
        }
        return rssfeed.disableUntil < theTimeRightNow;
      })
      .filter((rssfeed) => {
        return rssfeed.trainlabels?.indexOf(trainLabel.id) !== -1;
      });
  };

  const corsProxies = () =>
    corsproxies().filter((corsproxy) => !corsproxy.disabled);

  const fetchRssParams = createMemo(() => ({
    rssFeeds: rssFeedsForTrainLabel()?.map(
      (rssfeed: RssfeedType) => rssfeed.address,
    ),
    corsProxies: corsProxies()
      .filter((corsproxy) => corsproxy.disabled !== true)
      .map((corsproxy) => corsproxy.address),
  }));

  const [
    fetchedRSSPosts,
    {
      mutate: mutateRssPosts,
      //, refetch: fetchRssPosts
    },
  ] = createResource(() => fetchRssParams(), fetchRssPosts);

  const parsedRSSPosts = createMemo(() => {
    const posts = fetchedRSSPosts();
    return posts ? parsePosts(posts) : [];
  });

  const preppedRSSPosts = createMemo(() => {
    const posts = parsedRSSPosts();
    if (!posts) return [];

    return posts.filter(
      (post) =>
        post &&
        `${post.mlText}`.trim() !== "" &&
        post.postTitle != null &&
        (post.feedLink != null || post.guid != null)
    );
  });


  const [processedRSSPosts, setProcessedRSSPosts] = createSignal("[]");

  const ydocProcessedPosts = new yjs.Doc();

  let processedPostsIndexeDBProvider;

  createEffect(async () => {
    const trainLabel = trainlabels().find((trainlabel) => {
      return trainlabel.label === params.trainlabel;
    });
    if (trainLabel === undefined) {
      return;
    }
    if (ydocProcessedPosts === undefined) {
      return;
    }
    processedPostsIndexeDBProvider = new IndexeddbPersistence(
      `processed-posts-${params.trainlabel}`,
      ydocProcessedPosts,
    );
    const channelForProcessedPosts = channels().find(
      (channel) => channel?.label === `processed-posts-${params.trainlabel}`,
    );

    const recipientsForProcessedPosts = subscribers()
      .filter(
        (identity) =>
          channelForProcessedPosts?.subscribers?.indexOf(identity.id) !== -1,
      )
      .map((identity) => {
        return identity.recipient;
      });

    const identityForProcessedPosts = subscribers()
      .filter(
        (subscriber) =>
          channelForProcessedPosts?.subscribers?.indexOf(subscriber.id) !== -1,
      )
      .filter((subscriber) => subscriber.identity !== undefined)
      .map((subscriber) => {
        return subscriber.identity;
      });

    const signerForProcessedPosts = nostrKeys().find(
      (nostrKey) => nostrKey.id === channelForProcessedPosts.signer,
    );

    const dexieAdapter = new NDKCacheAdapterDexie({
      dbName: `ndk-cache-${encodeURI(channelForProcessedPosts?.label)}`,
    });
    const explicitRelayUrls = nostrRelays()
      ? nostrRelays()
          .filter((nostrRelay) => {
            return channelForProcessedPosts.nostrRelays !== undefined;
          })
          .filter((nostrRelay) => {
            return (
              channelForProcessedPosts.nostrRelays?.indexOf(nostrRelay.id) !==
              -1
            );
          })
          .map((nostrRelay) => nostrRelay.address)
      : [];

    const { type, data } = signerForProcessedPosts?.nsec
      ? nip19.decode(signerForProcessedPosts?.nsec)
      : { type: undefined, data: undefined };

    const ndkSignerForProcessedPosts = !!data
      ? new NDKPrivateKeySigner(data)
      : new NDKNip07Signer();

    const ndkOptsForProcessedPosts = {
      explicitRelayUrls: explicitRelayUrls,
      signer: ndkSignerForProcessedPosts,
      cacheAdapter: dexieAdapter,
    };

    const roomNdk = new NDK(ndkOptsForProcessedPosts);
    const secretNostrKey = data;
    await roomNdk.connect();

    const nostrProvider = new NostrProvider({
      yjs,
      ydoc: ydocProcessedPosts,
      nostrRoomCreateEventId: channelForProcessedPosts.nostrRoomEventId,
      ndk: roomNdk,
      YJS_UPDATE_EVENT_KIND: nostrCrdtEventKind,
      secretNostrKey,
      explicitRelayUrls,
      encrypt: (input: string) => {
        const e = new Encrypter();
        if (recipientsForProcessedPosts.length < 1) {
          return input;
        }
        recipientsForProcessedPosts.forEach((recipient) =>
          e.addRecipient(recipient),
        );
        if (recipientsForProcessedPosts.length > 0) {
          e.encrypt(input).then((encrypted) => {
            return armor.encode(encrypted);
          });
        }
        return input;
      },
      decrypt: (input: any) => {
        if (recipientsForProcessedPosts.length < 1) {
          return input;
        }
        const d = new Decrypter();
        try {
          d.addIdentity(identityForProcessedPosts);
          d.decrypt(armor.decode(input)).then((cleartext) => {
            return cleartext;
          });
        } finally {
          return input;
        }
      },
    });
    try {
      nostrProvider?.initialize();
    } catch (error) {
      // console.log(error);
    }
  });

  const yProcessedPosts = ydocProcessedPosts.getMap();

  ydocProcessedPosts?.on("update", () => {
    if (
      yProcessedPosts.get(`processed-posts-${params.trainlabel}`) === undefined
    ) {
      return;
    }
    const newProcessedRssposts = yProcessedPosts.get(
      `processed-posts-${params.trainlabel}`,
    );
    setProcessedRSSPosts(newProcessedRssposts);
  });

  const unprocessedRSSPosts = createMemo(() => {
    const posts = preppedRSSPosts() ?? [];

    if (!hideProcessedPosts()) {
      return posts;
    }

    const processed = processedRSSPosts();
    if (!processed) {
      return posts;
    }

    const processedPosts = JSON.parse(processed).flat();

    if (processedPosts.length === 0) {
      return posts;
    }

    return posts.filter(
      (postItem) =>
        !processedPosts.some(
          (processedPost) =>
            similarity(`${processedPost.mlText}`, `${postItem.mlText}`) > 0.8
        )
    );
  });

  const [classifier, setClassifier] = createSignal("{}");

  const ydocClassifier = new yjs.Doc();
  let classifierIndexeDBProvider;

  createEffect(async () => {
    const trainLabel = trainlabels().find((trainlabel) => {
      return trainlabel.label === params.trainlabel;
    });
    if (trainLabel === undefined) {
      return;
    }
    if (ydocClassifier === undefined) {
      return;
    }
    classifierIndexeDBProvider = new IndexeddbPersistence(
      `classifier-${params.trainlabel}`,
      ydocClassifier,
    );
    const channelForClassifier = channels().find(
      (channel) => channel?.label === `classifier-${params.trainlabel}`,
    );

    const recipientsForClassifier = subscribers()
      .filter(
        (identity) =>
          channelForClassifier?.subscribers?.indexOf(identity.id) !== -1,
      )
      .map((identity) => {
        return identity.recipient;
      });

    const identityForClassifier = subscribers()
      .filter(
        (subscriber) =>
          channelForClassifier?.subscribers?.indexOf(subscriber.id) !== -1,
      )
      .filter((subscriber) => subscriber.identity !== undefined)
      .map((subscriber) => {
        return subscriber.identity;
      });
    const signerForClassifier = nostrKeys().find(
      (nostrKey) => nostrKey.id === channelForClassifier.signer,
    );

    const dexieAdapter = new NDKCacheAdapterDexie({
      dbName: `ndk-cache-${encodeURI(channelForClassifier?.label)}`,
    });
    const explicitRelayUrls = nostrRelays()
      ? nostrRelays()
          .filter((nostrRelay) => {
            return channelForClassifier.nostrRelays !== undefined;
          })
          .filter((nostrRelay) => {
            return (
              channelForClassifier.nostrRelays?.indexOf(nostrRelay.id) !== -1
            );
          })
          .map((nostrRelay) => nostrRelay.address)
      : [];

    const { type, data } = signerForClassifier?.nsec
      ? nip19.decode(signerForClassifier?.nsec)
      : { type: undefined, data: undefined };

    const ndkSignerForClassifier = !!data
      ? new NDKPrivateKeySigner(data)
      : new NDKNip07Signer();

    const ndkOptsForClassifier = {
      explicitRelayUrls: explicitRelayUrls,
      signer: ndkSignerForClassifier,
      cacheAdapter: dexieAdapter,
    };
    const roomNdk = new NDK(ndkOptsForClassifier);
    const secretNostrKey = data;
    await roomNdk.connect();

    const nostrProvider = new NostrProvider({
      yjs,
      ydoc: ydocClassifier,
      nostrRoomCreateEventId: channelForClassifier.nostrRoomEventId,
      ndk: roomNdk,
      YJS_UPDATE_EVENT_KIND: nostrCrdtEventKind,
      secretNostrKey,
      explicitRelayUrls,
      encrypt: (input: string) => {
        const e = new Encrypter();
        if (recipientsForClassifier.length < 1) {
          return input;
        }
        recipientsForClassifier.forEach((recipient) =>
          e.addRecipient(recipient),
        );
        if (recipientsForClassifier.length > 0) {
          e.encrypt(input).then((encrypted) => {
            return armor.encode(encrypted);
          });
        }
        return input;
      },
      decrypt: (input: any) => {
        if (recipientsForClassifier.length < 1) {
          return input;
        }
        const d = new Decrypter();
        try {
          d.addIdentity(identityForClassifier);
          d.decrypt(armor.decode(input)).then((cleartext) => {
            return cleartext;
          });
        } finally {
          return input;
        }
      },
    });
    try {
      nostrProvider?.initialize();
    } catch (error) {
      console.log(error);
    }
  });

  const yClassifier = ydocClassifier.getMap();

  ydocClassifier?.on("update", () => {
    yClassifier.get(`classifier-${params.trainlabel}`);
    const newClassifier = yClassifier.get(`classifier-${params.trainlabel}`);
    if (newClassifier === undefined) {
      return;
    }
    setClassifier(() => newClassifier);
  });

  const [rssPosts, setRSSPosts] = createSignal([]);

  createEffect(() => {
    const theClassifier = JSON.parse(classifier());
    const suppressOdds = parseFloat(
      theClassifier["thresholdSuppressOdds"] || "999",
    );
    const winkClassifier = WinkClassifier();
    winkClassifier.definePrepTasks([prepNLPTask]);
    winkClassifier.defineConfig({
      considerOnlyPresence: true,
      smoothingFactor: 0.5,
    });
    const classifierModel = theClassifier["model"];
    if (classifierModel != undefined) {
      winkClassifier.importJSON(classifierModel);
    }
    if (unprocessedRSSPosts().length === 0) {
      return;
    }
    if (winkClassifier === undefined) {
      return
    }
    const newScoredRSSPosts = scoreRSSPosts(
      unprocessedRSSPosts(),
      winkClassifier,
    )
      .sort((a: any, b: any) =>
        a.prediction.suppress > b.prediction.suppress ? 1 : -1,
      )
      .filter(
        (post: {
          prediction: {
            promote: number;
          };
        }) => {
          if (suppressOdds == undefined) {
            return true;
          }
          if (post.prediction.promote == undefined) {
            return true;
          }
          return post.prediction.promote >= suppressOdds * -1;
        },
      );
    setRSSPosts(newScoredRSSPosts);
  });

  const train = (trainParams) => {
    const oldClassifier = JSON.parse(classifier() || "{}");
    const thresholdSuppressOdds: string =
      oldClassifier.thresholdSuppressOdds || "999";

    const winkClassifier = WinkClassifier();
    winkClassifier.definePrepTasks([prepNLPTask]);
    winkClassifier.defineConfig({
      considerOnlyPresence: true,
      smoothingFactor: 0.5,
    });
    if (oldClassifier.model != undefined) {
      winkClassifier.importJSON(oldClassifier.model);
    }
    winkClassifier.learn(trainParams.mlText, trainParams.mlClass);
    const newModel: string = winkClassifier.exportJSON();
    const newClassifier = JSON.stringify(
      removeEmpties({
        id: (Math.random() + 1).toString(36).substring(2),
        thresholdSuppressDocCount: 2,
        thresholdPromoteDocCount: 2,
        thresholdSuppressOdds: 99,
        channelsForClassifier: channels()
          .filter((channel) => {
            return channel?.label === `classifier-${params.trainlabel}`;
          })
          .map((channel) => channel.id),
        channelsForProcessedPosts: channels()
          .filter((channel) => {
            return channel?.label === `processed-posts-${params.trainlabel}`;
          })
          .map((channel) => channel.id),
        ...oldClassifier,
        label: params.trainlabel,
        model: newModel,
      }),
    );
    yClassifier.set(`classifier-${params.trainlabel}`, newClassifier);

    connections()
      .filter((connection) => {
        return connection.disabled === false;
      })
      .forEach((connection) => {
        if (JSON.parse(classifier() || "{}")?.payAmount === undefined) {
          return;
        }
        if (JSON.parse(classifier() || "{}")?.payAmount === "") {
          return;
        }
        const ln = new LN(connection.connectionUri);
        ln.pay(
          "chocolatesuperb163753@getalby.com",
          SATS(parseInt(JSON.parse(classifier() || "{}").payAmount)),
        );
        // ln.pay(theChannel.lightningAddress, SATS(parseInt(payAmount())));
      });
  };

  const markProcessed = (params: { mlText: string; trainLabel: string }) => {
    const { mlText, trainLabel } = params;
    const newProcessedPost = { mlText: mlText, lastSeen: Date.now() };
    const newProcessedPosts = JSON.parse(processedRSSPosts() || "[]")
      .flat()
      .filter((processedPost) => processedPost !== undefined)
      .filter((processedPost) => {
        return processedPost.mlText !== mlText;
      })
      .concat(newProcessedPost);
    yProcessedPosts.set(
      `processed-posts-${trainLabel}`,
      JSON.stringify(newProcessedPosts),
    );
  };

  createEffect(() => {
    i18n.locale(locale());
  });

  return (
    <div>
      <Nav />
      <SectionHeader>{`${i18n.t("rssposts")} -  ${params.trainlabel}`}
      </SectionHeader>
      <div class="flex flex-col">
        <Checkbox
          data-testid={`rssposts-hide-processed-posts`}
          label-text={<>{i18n.t("hide-processed-posts")}</>}
          id={`rssposts-hide-processed-posts-false`}
          checked={hideProcessedPosts()}
          onChange={(newValue) => {
            setHideProcessedPosts(!hideProcessedPosts());
          }}
            // ref onInput onBlur label testid
        />
        <Checkbox
          data-testid={`rssposts-trainmode`}
          label-text={<>{i18n.t("train-mode")}</>}
          id={`rssposts-train-mode`}
          checked={trainMode()}
          onChange={() => {
            setTrainMode(!trainMode());
          }}
          // ref onInput onBlur label testid
        />
        <Checkbox
          data-testid={`rssposts-hide-url`}
          label-text={<>{i18n.t("hide-url")}</>}
          id={`rssposts-hide-url`}
          checked={hideURL()}
          onChange={() => {
            setHideURL(!hideURL())
          }}
          // ref onInput onBlur label testid
        />
      </div>
      <div>
        <div top-30 overflow-y-auto class="no-scrollbar">
          <div h-20>
            {`${i18n.t("unprocessed")}: `}
            <Button
              testid={"mark-all-processed"}
              class="ml-0 pl-0"
              title={i18n.t("mark-all-processed")}
              label={`${rssPosts().length}`}
              onClick={() => {
                console.log('mark all read started')
                rssPosts().forEach(post => {
                  console.log(post.mlText)
                  console.log(rssPosts().length)
                  markProcessed({
                    mlText: post.mlText,
                    trainLabel: `${params.trainlabel}`,
                  })
                })
                console.log('mark all read complete')
              }}
            />
          </div>
          <For
            each={rssPosts()}
            fallback={
              <div class="pl-6">
                <SkeletonPost /> <SkeletonPost />
              </div>
            }
          >
            {(post) => {
              if (post === undefined) {
                return <></>
              }
              return (
                <>
                  <div ml-5>
                    <hr class="border-0 border-t border-gray-300 my-4" />
                    <Show when={trainMode()}>
                      <div class="flex1">
                        <PostTrain
                          trainLabel={`${params.trainlabel}`}
                          train={(mlClass: string) => {
                            const trainParams = {
                              mlClass: mlClass,
                              mlText: post.mlText,
                            };
                            train(trainParams);
                          }}
                          mlText={post.mlText}
                          prediction={post.prediction}
                          docCount={post.docCount}
                          markComplete={() => {
                            markProcessed({
                              mlText: post.mlText,
                              trainLabel: `${params.trainlabel}`,
                            })
                          }}
                        />

                      </div>
                    </Show>
                    <PostDisplay {...post} hideURL={hideURL()} />
                  </div>
                </>
              )
            }}
          </For>
        </div>
      </div>
    </div>
  )
}

// A few things jump out immediately — there’s solid architecture here, but the component is doing way too much. You’ve got:

// RSS fetching
// parsing
// ML scoring
// Yjs persistence
// Nostr sync
// encryption
// classifier training
// UI rendering

// …all inside one reactive component. That’s going to create subtle reactive loops, duplicate subscriptions, memory leaks, and hard-to-debug timing issues.

// Here are the highest-value improvements.

// 1. Your createEffects are over-firing

// You have many effects that:

// create providers
// connect relays
// instantiate DBs
// register listeners

// Those should almost never live in raw createEffect.

// Example:

// createEffect(() => {
//   const ndk = new NDK(ndkOpts);
//   ndk.connect().then(() => {
//     ...
//   });
// });

// Every dependency change recreates connections.

// You likely have:

// duplicate websocket connections
// duplicate Yjs providers
// duplicate event handlers
// leaked IndexedDB persistence instances
// Better pattern

// Use createMemo for derived state.

// Use onMount / onCleanup for lifecycle resources.

// Example:

// const ndk = createMemo(() => {
//   return new NDK({
//     explicitRelayUrls: relayUrls(),
//     signer: signer(),
//     cacheAdapter: cache(),
//   });
// });

// onMount(async () => {
//   await ndk().connect();

//   const provider = new NostrProvider(...);

//   provider.initialize();

//   onCleanup(() => {
//     provider.destroy?.();
//     ndk().disconnect?.();
//   });
// });
//
// 2. == [] never works

// You have:

// if (newRssFeedsForTrainLabel == []) {
//   return;
// }

// Arrays compare by reference.

// This is always false.

// Use:

// if (newRssFeedsForTrainLabel.length === 0)
// 3. Huge anti-pattern: repeated JSON.parse

// This is everywhere:

// JSON.parse(classifier() || "{}")

// You parse the same signal repeatedly inside effects.

// That’s:

// expensive
// noisy
// unsafe
// Better
// const classifierData = createMemo(() => {
//   try {
//     return JSON.parse(classifier() || "{}");
//   } catch {
//     return {};
//   }
// });

// Then:

// classifierData().model
// classifierData().thresholdSuppressOdds

// Do the same for processedRSSPosts.

// 4. Yjs event listeners are leaking

// This:

// ydocProcessedPosts?.on("update", () => {

// is outside lifecycle cleanup.

// Every render/module reload can accumulate listeners.

// Use:

// onMount(() => {
//   const handler = () => { ... };

//   ydocProcessedPosts.on("update", handler);

//   onCleanup(() => {
//     ydocProcessedPosts.off("update", handler);
//   });
// });

// Same for classifier doc.

// 5. Derived signals should be memos

// You use effects for pure derivation:

// createEffect(() => {
//   const newCorsProxies = corsproxies().filter(...)
//   setCorsProxies(newCorsProxies)
// })

// That should be:

// const corsProxies = createMemo(() =>
//   corsproxies().filter((c) => !c.disabled)
// );

// You can eliminate many signals.

// 6. This component should be split aggressively

// This is probably the biggest issue long-term.

// You want composables/hooks for:

// Suggested extraction
// useClassifier()

// Handles:

// wink classifier
// import/export
// training
// thresholds
// useProcessedPosts()

// Handles:

// Yjs map
// IndexedDB persistence
// mark processed
// useNostrSync()

// Handles:

// NDK
// providers
// relay lifecycle
// useRSSFeedPipeline()

// Handles:

// fetch
// parse
// preprocess
// score

// Right now your UI component contains infrastructure code.

// 7. Potential infinite reactive loops

// This pattern is dangerous:

// createEffect(() => {
//   ...
//   setFetchRssParams(newFetchRSSParams);
// });

// Then:

// createResource(() => fetchRssParams(), fetchRssPosts);

// Every object identity change retriggers resource fetches.

// Even if values are identical.

// Better

// Use memo:

// const fetchRSSParams = createMemo(() => ({
//   rssFeeds: rssFeedsForTrainLabel().map(...),
//   corsProxies: corsProxies().map(...),
// }));

// Or stabilize with reconcile.

// 8. Incorrect empty object comparisons

// You have:

// if (classifier() == {}) {

// Always false.

// Use:

// if (Object.keys(classifierData()).length === 0)
// 9. Async race conditions

// This:

// parsePosts(fetchedRSSPosts()).then(...)

// inside effects can race if resources update quickly.

// You can end up setting stale parsed posts.

// Use createResource chains instead.

// Example:

// const [parsedPosts] = createResource(
//   fetchedRSSPosts,
//   parsePosts
// );

// Solid handles cancellation better.

// 10. You’re recreating WinkClassifier repeatedly

// Inside effects + train function:

// const winkClassifier = WinkClassifier();

// This should probably be memoized or wrapped.

// Classifier initialization is not free.

// 11. Encryption/decryption closures are duplicated

// You repeat:

// encrypt: (input) => ...
// decrypt: (input) => ...

// multiple times.

// Extract:

// function createCryptoHandlers(...) {
//   return {
//     encrypt(input) { ... },
//     decrypt(input) { ... },
//   };
// }
// 12. Types are mostly missing

// You’ve got lots of:

// createSignal([])

// which becomes any[].

// And:

// const train = (params) => {

// Strong typing would catch several bugs here.

// Especially:

// classifier shape
// rss post shape
// processed post shape
// channel shape
// 13. This line is suspicious
// <div flex flex-row>

// Those aren’t valid JSX props unless using Uno/Windi macros.

// Probably intended:

// <div class="flex flex-row">
// 14. Bug here
// setHideProcessedPosts(props.trainLabel?.id, newValue);

// But component prop is:

// props.trainlabel

// (lowercase l)

// 15. This can throw
// channelForProcessedPosts.signer

// if channel is undefined.

// You guard some places but not others.

// You need optional chaining consistently.

// Biggest architectural recommendation

// Right now this component is mixing:

// state orchestration
// network lifecycle
// distributed sync
// persistence
// ML
// rendering

// Solid works best when:

// components render
// hooks/services orchestrate

// This file feels closer to a backend service than a UI component.

// If you split it into:

// 4–5 composables
// pure memos
// fewer imperative effects

// …the complexity drops dramatically.

// Immediate wins I'd do first
// Replace derivation createEffects with createMemo
// Fix all == [] / == {}
// Add cleanup to every Yjs/NDK listener
// Extract Nostr/Yjs sync into hooks
// Remove repeated JSON.parse
// Convert async effect chains into createResource chains

// Those six changes alone would make this substantially more stable.

ChatGPT said:
Yes — this makes the signing error much clearer.

The key line is:

const { type, data } = signerForProcessedPosts?.nsec
  ? nip19.decode(signerForProcessedPosts?.nsec)
  : { type: undefined, data: undefined };

const secretNostrKey = data;


nip19.decode(nsec) returns the private key as a Uint8Array, so the key type is probably not the problem.

The bigger problem is that your encrypt() implementation is incorrect for the API your NostrProvider expects.

1. Your encrypt() is asynchronous but returns synchronously
You currently have:

encrypt: (input: string) => {
  const e = new Encrypter();

  if (recipientsForProcessedPosts.length < 1) {
    return input;
  }

  recipientsForProcessedPosts.forEach((recipient) =>
    e.addRecipient(recipient),
  );

  if (recipientsForProcessedPosts.length > 0) {
    e.encrypt(input).then((encrypted) => {
      return armor.encode(encrypted);
    });
  }

  return input;
},


The .then() return value is discarded.

So this:

e.encrypt(input).then(...)


does not cause encrypt() to return the encrypted value.

It always eventually does:

return input;


That's a separate bug from your current serializeEvent error, but it needs fixing.

2. More importantly: your provider expects synchronous encryption
In the code you showed earlier:

const encrypted =
  this.encrypt(chunk);

const content =
  toBase64(encrypted);


That means NostrProvider expects:

encrypt(Uint8Array) -> Uint8Array


or at least a synchronous binary-compatible result.

It cannot currently handle:

encrypt(Uint8Array) -> Promise<Uint8Array>


So age-encryption can't simply be dropped into that callback unless you make publishUpdates() asynchronous with:

const encrypted = await this.encrypt(chunk);


3. Your TypeScript annotation is also lying
You have:

encrypt: (input: string) => {


But chunk is a Yjs binary update:

const chunk = ...


and ultimately:

this.encrypt(chunk)


So this should conceptually be:

encrypt: (input: Uint8Array) => ...


The same applies to decrypt.

But your actual serializeEvent error is probably this
Look at:

const { type, data } = signerForProcessedPosts?.nsec
  ? nip19.decode(signerForProcessedPosts?.nsec)
  : { type: undefined, data: undefined };


You never verify type.

If nsec isn't actually an nsec, nip19.decode() can return something other than the private-key representation you expect.

Add:

const decoded = signerForProcessedPosts?.nsec
  ? nip19.decode(signerForProcessedPosts.nsec)
  : undefined;

if (
  decoded &&
  decoded.type !== "nsec"
) {
  throw new Error(
    `Expected nsec, got ${decoded.type}`,
  );
}

const secretNostrKey = decoded?.data;


And immediately before constructing NostrProvider:

console.log("Nostr signing key", {
  type: secretNostrKey?.constructor?.name,
  length: secretNostrKey?.length,
  kind: nostrCrdtEventKind,
});


You want:

type: "Uint8Array"
length: 32
kind: 7777


There's another likely problem in your NDK setup
You're doing both:

const ndkSignerForProcessedPosts =
  !!data
    ? new NDKPrivateKeySigner(data)
    : new NDKNip07Signer();


and:

const secretNostrKey = data;


Then your provider does this:

if (secretNostrKey === undefined) {
   // NDK signs
} else {
   // nostr-tools signs
}


So you're actually maintaining two signing paths.

When data exists:

NDK
 └── has NDKPrivateKeySigner

NostrProvider
 └── ignores NDK signer
 └── uses secretNostrKey
 └── finalizeEvent()
 └── nostr-tools signs


That isn't necessarily wrong, but it makes debugging harder.

I would test this first
Temporarily change your provider construction to:

const secretNostrKey = data;

console.log("=== NOSTR DEBUG ===");
console.log("decoded nsec type:", type);
console.log(
  "secret key constructor:",
  secretNostrKey?.constructor?.name,
);
console.log(
  "secret key length:",
  secretNostrKey?.length,
);
console.log(
  "secret key instanceof Uint8Array:",
  secretNostrKey instanceof Uint8Array,
);
console.log(
  "event kind:",
  nostrCrdtEventKind,
  typeof nostrCrdtEventKind,
);
console.log("relay URLs:", explicitRelayUrls);


If you get:

decoded nsec type: nsec
secret key constructor: Uint8Array
secret key length: 32
secret key instanceof Uint8Array: true
event kind: 7777 number


then the key and kind are fine.

I would also modify publishEvent() to expose the actual bad property
In your @ashby-shoal/y-ndk code, change:

const signedEvent = finalizeEvent(
  eventTemplate,
  secretNostrKey,
);


temporarily to:

console.log("FINALIZE INPUT", {
  eventTemplate,
  secretNostrKeyType:
    secretNostrKey?.constructor?.name,
  secretNostrKeyLength:
    secretNostrKey?.length,
});

const signedEvent = finalizeEvent(
  eventTemplate,
  secretNostrKey,
);


I strongly suspect you'll discover one of these:

secretNostrKeyType: undefined


or

secretNostrKeyType: String


or a malformed event field.

And there's a very important issue with your room creation
Your earlier createNostrCRDTRoom() can call:

const firstEvent = await publishEvent(...)
roomId = firstEvent.id;


With the NDK branch, event.id exists.

With the finalizeEvent() branch, it also exists.

So that's fine.

But your subsequent updates use:

["e", this.nostrRoomCreateEventId]


and your initialize() subscription currently does:

{
  kinds: [
    this.YJS_UPDATE_EVENT_KIND,
  ],
}


without filtering by the room ID.

That means every channel using kind 7777 can potentially be fed into this provider.

You probably want the subscription to include the room:

{
  kinds: [this.YJS_UPDATE_EVENT_KIND],
  "#e": [this.nostrRoomCreateEventId],
}


although you'll need to account for the initial room-creation event, which intentionally doesn't have the e tag.

One more serious bug: your age encryption is currently doing nothing
This:

e.encrypt(input).then((encrypted) => {
  return armor.encode(encrypted);
});

return input;


means the Nostr event receives the unencrypted Yjs update.

So despite having:

recipientsForProcessedPosts


configured, your published event is currently plaintext.

You need the provider API to support async encryption, e.g.:

const encrypted = await this.encrypt(chunk);
const content = toBase64(encrypted);


and then:

encrypt: async (input) => {
  const e = new Encrypter();

  for (const recipient of recipientsForProcessedPosts) {
    e.addRecipient(recipient);
  }

  const encrypted = await e.encrypt(input);

  return armor.encode(encrypted);
},


But armor.encode() likely produces a string, while your current toBase64() expects binary. So the encryption contract needs to be explicitly designed as either:

Uint8Array -> Uint8Array


or:

Uint8Array -> string


rather than mixing the two.

My recommended debugging order
Verify secretNostrKey
console.log(data?.constructor?.name, data?.length);


It should be Uint8Array, 32.
Verify YJS_UPDATE_EVENT_KIND
console.log(nostrCrdtEventKind, typeof nostrCrdtEventKind);


It should be 7777, "number".
Log the exact eventTemplate immediately before finalizeEvent().
Temporarily disable encryption — you already effectively are because your function returns input. This removes age from the equation.
Once signing works, fix the encryption API separately.
The pasted component makes me lean away from the private key itself and toward the exact value reaching finalizeEvent(). The next most useful thing would be the output of those four debug values, especially secretNostrKey?.constructor?.name, secretNostrKey?.length, and the logged eventTemplate.



You said:

Uint8Array(32) [33, 13, 143, 70, 188, 185, 46, 247, 95, 136, 139, 91, 254, 51, 21, 136, 6, 140, 57, 80, 164, 248, 69, 138, 204, 247, 98, 21, 155, 45, 178, 38, buffer: ArrayBuffer(32), byteLength: 32, byteOffset: 0, length: 32, Symbol(Symbol.toStringTag): 'Uint8Array']
y-ndk-CR27Wf8H.js:271 [YJS] COMPLETE CHUNK BATCH {batchId: '5327de6d-29aa-4211-8ca8-4c03c6857621', total: 1, received: 1}
y-ndk-CR27Wf8H.js:271 Failed to reassemble Yjs chunk batch: Error: Unexpected end of array
    at P (yjs-BY62V4R8.js:1:5423)
    at yjs-BY62V4R8.js:1:5514.    // Based on:
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
  console.log(eventTemplate)
  console.log(secretNostrKey)
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
      console.log("[YJS] COMPLETE CHUNK BATCH", {
        batchId,
        total: batch.total,
        received: batch.received,
      });
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
            "#e": [this.nostrRoomCreateEventId],
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

ChatGPT said:
That output changes the diagnosis substantially.

Your Nostr signing problem is fixed. The private key is exactly what finalizeEvent() wants:

Uint8Array(32)

And you're now getting:

[YJS] COMPLETE CHUNK BATCH { total: 1, received: 1 }
Failed to reassemble Yjs chunk batch:
Error: Unexpected end of array

So the current corruption is happening before or during mergeUpdates().

The biggest bug is your encrypt/decrypt contract
In your caller, you have:

encrypt: (input: string) => {
  ...
  return input;
},

and:

decrypt: (input: any) => {
  ...
  return input;
},

That is okay while encryption is disabled.

But look at what publishUpdates() does:

const chunk = chunks[i];

const encrypted = this.encrypt(chunk);

const content = toBase64(encrypted);

Then on receipt:

update = this.decrypt(
  fromBase64(event.content),
);

If encryption is truly passthrough, the round trip should be:

Yjs Uint8Array
       ↓
toBase64()
       ↓
Nostr content string
       ↓
fromBase64()
       ↓
same Yjs Uint8Array
       ↓
mergeUpdates()

The fact that mergeUpdates() says:

Unexpected end of array

means the bytes coming out of fromBase64() aren't the same complete Yjs update that went in.

I would prove that first
Add this around publication:

const chunk = chunks[i];

console.log("[YJS] OUTGOING CHUNK", {
  batchId,
  index: i,
  total,
  bytes: chunk.byteLength,
});

const encrypted = this.encrypt(chunk);

console.log("[YJS] AFTER ENCRYPT", {
  constructor: encrypted?.constructor?.name,
  bytes: encrypted?.byteLength,
  length: encrypted?.length,
});

const content = toBase64(encrypted);

console.log("[YJS] BASE64", {
  chars: content.length,
});

Then on receipt:

const encoded = event.content;

const decoded = fromBase64(encoded);

console.log("[YJS] INCOMING CHUNK", {
  eventId: event.id,
  encodedChars: encoded.length,
  decodedConstructor: decoded?.constructor?.name,
  decodedBytes: decoded?.byteLength,
});

And most importantly:

console.log(
  "[YJS] FIRST BYTES",
  Array.from(decoded.slice(0, 20)),
);

Compare the outgoing and incoming byte lengths.

If you publish:

OUTGOING CHUNK bytes: 1234

but receive:

INCOMING CHUNK decodedBytes: 1233

or anything different, you've found the problem.

There's also a conceptual problem with your chunking implementation
You say:

We never split an individual Yjs update by slicing its bytes.

Good.

But then:

chunks.push(
  yjs.mergeUpdates(current),
);

is creating a single Yjs update containing multiple updates.

That's valid.

However, your initial-state code does this:

const initialChunks =
  splitUpdatesIntoChunks(
    yjs,
    [initialLocalState],
    NOSTR_UPDATE_CHUNK_BYTES,
  );

Since initialLocalState is already one Yjs update, this will never actually chunk it.

If:

initialLocalState = 100 KiB

then:

if (size > maxBytes) {
  throw new Error(...)
}

So your comment saying initial state is chunked isn't quite true.

That's not the current Unexpected end of array error, but it's worth fixing architecturally.

More importantly: your subscription filter introduced a historical-event problem
You changed this to:

{
  kinds: [
    this.YJS_UPDATE_EVENT_KIND,
  ],
  "#e": [this.nostrRoomCreateEventId],
}

That's correct for normal update events, because they contain:

["e", roomId]

But your room creation event deliberately does not contain the e tag:

tags: [
  ["crdt", label],
  createChunkTag(batchId, 0, total),
]

Therefore your room's first event is now excluded from initialization.

That's a serious bug.

You have two types of events:

Creation event
["crdt", label]
["chunk", batchId, "0", "1"]

Update event
["e", roomId]
["chunk", batchId, "0", "1"]

Your subscription only gets the second type.

But I think there's an even more important issue
Your log says:

total: 1
received: 1

So this isn't a chunk ordering problem.

You have exactly one event.

Then:

this.yjs.mergeUpdates(batch.chunks)

fails.

That means:

batch.chunks[0]

is not a valid Yjs update.

I'd put this directly before mergeUpdates():

console.log(
  "[YJS] CHUNK TYPE",
  batch.chunks.map((chunk) => ({
    constructor: chunk?.constructor?.name,
    byteLength: chunk?.byteLength,
    length: chunk?.length,
  })),
);

Then validate it:

for (const [i, chunk] of batch.chunks.entries()) {
  if (!(chunk instanceof Uint8Array)) {
    throw new Error(
      `Chunk ${i} is not Uint8Array: ${
        chunk?.constructor?.name
      }`,
    );
  }

  console.log(
    `[YJS] chunk ${i}: ${chunk.byteLength} bytes`,
  );
}

I suspect lib0/buffer is not your actual problem
This:

const content = toBase64(encrypted);

followed by:

const decoded = fromBase64(event.content);

should round-trip correctly.

So let's test it independently.

Inside publishUpdates():

const encoded = toBase64(chunk);
const decoded = fromBase64(encoded);

console.log(
  "LOCAL BASE64 ROUNDTRIP",
  chunk.byteLength,
  decoded.byteLength,
  arrayBuffersAreEqual(
    chunk.buffer.slice(
      chunk.byteOffset,
      chunk.byteOffset + chunk.byteLength,
    ),
    decoded.buffer.slice(
      decoded.byteOffset,
      decoded.byteOffset + decoded.byteLength,
    ),
  ),
);

You should get:

LOCAL BASE64 ROUNDTRIP 1234 1234 true

If that says true, the corruption is happening between publication and reception.

There is a very likely issue with your event history
Your initialize() does:

sub.on("event", (event) => {
  if (!eoseSeen) {
    initialEvents.push(event);
  } else {
    this.processIncomingEvent(event);
  }
});

Then:

sub.on("eose", () => {
  ...
  const usableInitialEvents =
    this.updateFromInitialEvents(initialEvents);

This is vulnerable to receiving your own freshly published event through the relay while initialization is still happening.

You can then have:

IndexedDB has local Yjs state.
initialize() subscribes.
Relay sends historical event.
Relay sends another event.
EOSE arrives.
You reconstruct history.
Local state gets diffed.
A newly published event arrives.
Chunk processing happens concurrently.
It's worth logging:

console.log("[NOSTR EVENT]", {
  id: event.id,
  created_at: event.created_at,
  tags: event.tags,
  contentLength: event.content.length,
});

I would make processIncomingEvent() much stricter
Replace this:

update = this.decrypt(
  fromBase64(event.content),
);

with:

const encoded = event.content;

if (typeof encoded !== "string") {
  console.error(
    "[YJS] Invalid Nostr content",
    event,
  );
  return;
}

let decoded;

try {
  decoded = fromBase64(encoded);
} catch (error) {
  console.error(
    "[YJS] Base64 decode failed",
    error,
  );
  return;
}

console.log("[YJS] decoded chunk", {
  eventId: event.id,
  encodedLength: encoded.length,
  decodedLength: decoded.byteLength,
});

let update;

try {
  update = this.decrypt(decoded);
} catch (error) {
  console.error(
    "[YJS] decrypt failed",
    error,
  );
  return;
}

if (!(update instanceof Uint8Array)) {
  console.error(
    "[YJS] decrypt did not return Uint8Array",
    {
      type: update?.constructor?.name,
      length: update?.length,
      byteLength: update?.byteLength,
    },
  );
  return;
}

batch.chunks[index] = update;

That will tell us exactly which boundary is broken.

One thing I would change immediately
Your unused function:

function toUint8Array(value) {

should actually be used.

Normalize everything entering the Yjs path:

update = toUint8Array(
  this.decrypt(
    fromBase64(event.content),
  ),
);

And before publishing:

const encrypted = toUint8Array(
  this.encrypt(chunk),
);

const content = toBase64(encrypted);

This eliminates differences between:

Uint8Array
ArrayBuffer
Uint8ClampedArray
Node Buffer
typed-array views
However, I think you have a second major bug waiting behind this one
Your age encryption code cannot work with the current API.

You currently have:

e.encrypt(input).then((encrypted) => {
  return armor.encode(encrypted);
});

return input;

Once you fix it, you'll need something like:

encrypt: async (input) => {
  const e = new Encrypter();

  for (const recipient of recipientsForProcessedPosts) {
    e.addRecipient(recipient);
  }

  const encrypted = await e.encrypt(input);

  return armor.encode(encrypted);
},

But then your provider must change to:

const encrypted =
  await this.encrypt(chunk);

And similarly decryption must become asynchronous:

const update =
  await this.decrypt(
    fromBase64(event.content),
  );

That means processIncomingEvent() becomes async.

So I'd first get the complete unencrypted binary round-trip working. Don't introduce age encryption until:

Yjs update
   ↓
mergeUpdates
   ↓
base64
   ↓
Nostr
   ↓
base64 decode
   ↓
mergeUpdates

works reliably.

One last thing: mergeUpdates() is not actually necessary here
For a batch containing one chunk:

this.yjs.mergeUpdates([
  update,
]);

should normally work, but it isn't buying you anything.

You can make the code safer:

const mergedUpdate =
  batch.total === 1
    ? batch.chunks[0]
    : this.yjs.mergeUpdates(
        batch.chunks,
      );

Then:

this.yjs.applyUpdate(
  this.ydoc,
  mergedUpdate,
  this,
);

This also gives you a useful diagnostic:

If total === 1 and:

this.yjs.applyUpdate(...)

fails with Unexpected end of array, then the received bytes themselves are definitely corrupted/truncated.

If applyUpdate() succeeds but mergeUpdates([update]) fails, then we'd know something very unusual is happening with the Yjs version/API.

So my next test would be exactly this
Change:

const mergedUpdate =
  this.yjs.mergeUpdates(
    batch.chunks,
  );

to:

const mergedUpdate =
  batch.total === 1
    ? batch.chunks[0]
    : this.yjs.mergeUpdates(
        batch.chunks,
      );

console.log("[YJS] FINAL UPDATE", {
  type: mergedUpdate?.constructor?.name,
  bytes: mergedUpdate?.byteLength,
});

this.yjs.applyUpdate(
  this.ydoc,
  mergedUpdate,
  this,
);

If that produces the same Unexpected end of array, send me the outgoing chunk byte length and incoming decoded byte length. Those two numbers should let us pinpoint whether the corruption is in your Base64/event transport or in the Yjs data being generated.



You said:

{kind: 7777, created_at: 1787145944, tags: Array(2), content: ''}
content
:
""
created_at
:
1787145944
kind
:
7777
pubkey
:
"b6f2c7a925558bb34c60dd6616647987b89f618e82a16de65e0a4b463f28b974"
tags
:
Array(2)
0
:
(2) ['e', undefined]
1
:
(4) ['chunk', 'bf3cf524-8d9a-4238-abcb-194107983992', '0', '1']
length
:
2
[[Prototype]]
:
Array(0)
[[Prototype]]
:
Object
@ashby-shoal_y-ndk.js?v=5776c50c:7159
Uint8Array(32) [205, 246, 27, 112, 49, 214, 212, 173, 133, 131, 94, 39, 35, 47, 169, 243, 120, 12, 119, 8, 146, 16, 8, 79, 33, 144, 172, 169, 165, 106, 89, 85, buffer: ArrayBuffer(32), byteLength: 32, byteOffset: 0, length: 32, Symbol(Symbol.toStringTag): 'Uint8Array']
rssposts.tsx:562 Failed to publish Yjs update: Error: can't serialize event with wrong or missing properties
setTimeout
markProcessed	@	rssposts.tsx:562
markComplete	@	rssposts.tsx:664
onClick	@	PostTrain.tsx:35

ChatGPT said:
Yes — this log exposes a different root cause from the earlier Unexpected end of array.

The smoking gun is:

{
  kind: 7777,
  created_at: 1787145944,
  tags: [
    ["e", undefined],
    ["chunk", "...", "0", "1"]
  ],
  content: ""
}

You have two separate bugs.

1. nostrRoomCreateEventId is undefined
This:

["e", this.nostrRoomCreateEventId]

is producing:

["e", undefined]

That's an invalid Nostr tag, and it explains:

Error: can't serialize event with wrong or missing properties

The important question is why NostrProvider is being constructed with:

nostrRoomCreateEventId: undefined

Your React/Solid code does:

const channelForClassifier = channels().find(
  (channel) =>
    channel?.label === `classifier-${params.trainlabel}`,
);

and then:

const nostrProvider = new NostrProvider({
  ...
  nostrRoomCreateEventId: channelForClassifier.nostrRoomEventId,
  ...
});

So before creating the provider, verify:

console.log("channelForClassifier", channelForClassifier);
console.log(
  "nostrRoomEventId",
  channelForClassifier?.nostrRoomEventId,
);

I would actually make this fail immediately:

if (!channelForClassifier) {
  throw new Error(
    `Missing classifier channel: classifier-${params.trainlabel}`
  );
}

if (!channelForClassifier.nostrRoomEventId) {
  throw new Error(
    `Channel classifier-${params.trainlabel} has no nostrRoomEventId`
  );
}

Do the same for channelForProcessedPosts.

2. Your encrypt() implementation is broken
This is the other major issue.

You currently have:

encrypt: (input: string) => {
  const e = new Encrypter();

  if (recipientsForClassifier.length < 1) {
    return input;
  }

  recipientsForClassifier.forEach((recipient) =>
    e.addRecipient(recipient),
  );

  if (recipientsForClassifier.length > 0) {
    e.encrypt(input).then((encrypted) => {
      return armor.encode(encrypted);
    });
  }

  return input;
},

The .then() return value is completely discarded.

So this:

e.encrypt(input).then((encrypted) => {
  return armor.encode(encrypted);
});
return input;

always returns input.

If e.encrypt() is asynchronous, your function needs to return a Promise:

return e.encrypt(input).then((encrypted) => {
  return armor.encode(encrypted);
});

But there's an even bigger problem.

Your publishUpdates() currently assumes encrypt() is synchronous:

const encrypted = this.encrypt(chunk);
const content = toBase64(encrypted);

Therefore you need to decide whether encryption is synchronous or asynchronous and make the provider consistent.

Given age-encryption, I'd make it async.

Change publishUpdates() to:
async publishUpdates(updates) {
  if (!updates || updates.length === 0) {
    return;
  }

  const chunks = splitUpdatesIntoChunks(
    this.yjs,
    updates,
    NOSTR_UPDATE_CHUNK_BYTES,
  );

  const batchId = crypto.randomUUID();
  const total = chunks.length;

  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];

    const encrypted = await this.encrypt(chunk);

    const content = toBase64(
      toUint8Array(encrypted),
    );

    const tags = [
      ["e", this.nostrRoomCreateEventId],
      createChunkTag(batchId, i, total),
    ];

    await publishEvent({
      ndk: this.ndk,
      pool,
      explicitRelayUrls: this.explicitRelayUrls,
      secretNostrKey: this.secretNostrKey,
      eventTemplate: {
        kind: this.YJS_UPDATE_EVENT_KIND,
        created_at: Math.floor(Date.now() / 1000),
        tags,
        content,
      },
    });
  }
}

And define encryption as:

encrypt: async (input) => {
  const e = new Encrypter();

  if (recipientsForClassifier.length === 0) {
    return input;
  }

  recipientsForClassifier.forEach((recipient) => {
    e.addRecipient(recipient);
  });

  const encrypted = await e.encrypt(input);

  return armor.encode(encrypted);
},

Then your default must also be async-compatible:

encrypt: async (input) => input,
decrypt: async (input) => input,

But that leads to the next issue.

3. decrypt() has the exact same bug
You have:

decrypt: (input: any) => {
  if (recipientsForClassifier.length < 1) {
    return input;
  }

  const d = new Decrypter();

  try {
    d.addIdentity(identityForClassifier);
    d.decrypt(armor.decode(input)).then((cleartext) => {
      return cleartext;
    });
  } finally {
    return input;
  }
},

This is particularly bad because the finally guarantees that the encrypted input is returned.

The async result is discarded.

It should be something like:

decrypt: async (input) => {
  if (recipientsForClassifier.length === 0) {
    return input;
  }

  const d = new Decrypter();

  d.addIdentity(identityForClassifier);

  return await d.decrypt(
    armor.decode(input),
  );
},

4. But don't make processIncomingEvent() accidentally async-unhandled
If you change decrypt to async, this:

update = this.decrypt(
  fromBase64(event.content),
);

doesn't give you the Uint8Array anymore.

It gives you a Promise.

So change:

processIncomingEvent = (event) => {

to:

processIncomingEvent = async (event) => {

and:

const update = await this.decrypt(
  fromBase64(event.content),
);

Likewise:

updateFromEvents(events)

needs to become async if decryption is async.

5. However, there's an even more important architectural issue
Your current encrypt/decrypt API from NostrProvider appears to have originally been designed as synchronous transformations.

You are trying to plug an asynchronous encryption library into it.

I'd avoid spreading async throughout the provider if possible.

Instead, make the provider explicitly support async crypto:

async encryptUpdate(update) {
  const encrypted = await this.encrypt(update);
  return toUint8Array(encrypted);
}

async decryptUpdate(content) {
  const decoded = fromBase64(content);
  const decrypted = await this.decrypt(decoded);
  return toUint8Array(decrypted);
}

Then the rest of your code is very explicit.

For example:

const encrypted = await this.encryptUpdate(chunk);

const content = toBase64(encrypted);

and:

const update = await this.decryptUpdate(
  event.content,
);

That's much safer than having random functions silently return either a Uint8Array or a Promise.

6. Your createNostrCRDTRoom() has the same problem
You have:

content: toBase64(
  encrypt(firstChunk),
),

If encrypt() becomes async, this becomes:

content: toBase64(Promise)

which is obviously wrong.

Change it to:

const encryptedFirstChunk =
  await encrypt(firstChunk);

const firstEvent = await publishEvent({
  ...
  eventTemplate: {
    ...
    content: toBase64(
      toUint8Array(encryptedFirstChunk),
    ),
  },
});

And similarly for the remaining chunks:

const encryptedChunk =
  await encrypt(chunk);

await publishEvent({
  ...
  eventTemplate: {
    ...
    content: toBase64(
      toUint8Array(encryptedChunk),
    ),
  },
});

7. Why your earlier Unexpected end of array happens
The earlier error:

[YJS] COMPLETE CHUNK BATCH
{ total: 1, received: 1 }

Failed to reassemble Yjs chunk batch:
Error: Unexpected end of array

now makes much more sense.

Your chunk itself was only:

Uint8Array(32)

That's suspiciously exactly 32 bytes.

A valid Yjs update isn't necessarily 32 bytes, but your encryption/decryption path is clearly not behaving correctly.

The likely flow is:

Yjs update
   ↓
encrypt()
   ↓
Promise / incorrect value
   ↓
base64
   ↓
Nostr
   ↓
fromBase64()
   ↓
decrypt()
   ↓
wrong/incomplete bytes
   ↓
Yjs.mergeUpdates()
   ↓
Unexpected end of array

So I would not change your chunk size or Yjs chunking algorithm yet.

Your chunking strategy is conceptually okay: you're merging complete Yjs updates and then putting the resulting update into one Nostr event.

The corruption is happening around serialization/encryption.

8. There is also a serious bug in room creation
You currently do:

const firstEvent = await publishEvent(...);

roomId = firstEvent.id;

But in publishEvent():

if (secretNostrKey === undefined) {
  const event = new NDKEvent(
    ndk,
    eventTemplate,
  );

  await event.publish();

  return event;
}

Fine.

But when secretNostrKey exists:

const signedEvent = finalizeEvent(
  eventTemplate,
  secretNostrKey,
);

await pool.publish(
  explicitRelayUrls,
  signedEvent,
);

return signedEvent;

Also fine.

But your room creation code can resolve to a completely unrelated event.

You have:

const sub = ndk.subscribe(
  {
    since: Math.floor(Date.now() / 1000) - 1,
    kinds: [YJS_UPDATE_EVENT_KIND],
  },
  {
    closeOnEose: true,
  },
);

sub.on("event", (event) => {
  if (!resolved) {
    resolved = true;
    resolve(event.id);
  }
});

That subscription isn't filtering by your room label or batch ID.

So the first event received can be some other kind-7777 event.

That can give you a completely wrong room ID.

For room creation, I would remove that subscription entirely if publishEvent() already gives you the published event.

Just:

const firstEvent = await publishEvent({
  ...
});

if (!firstEvent?.id) {
  throw new Error(
    "Room creation event has no ID",
  );
}

return firstEvent.id;

Much safer.

9. You should validate the room ID before publishing
Add this directly to publishUpdates():

if (!this.nostrRoomCreateEventId) {
  throw new Error(
    "Cannot publish Yjs update: nostrRoomCreateEventId is missing",
  );
}

And perhaps:

if (
  typeof this.nostrRoomCreateEventId !== "string" ||
  this.nostrRoomCreateEventId.length !== 64
) {
  throw new Error(
    `Invalid nostrRoomCreateEventId: ${
      this.nostrRoomCreateEventId
    }`,
  );
}

That would have caught your current failure before constructing the invalid event.

The immediate fix I'd make
In your Solid component, change:

const nostrProvider = new NostrProvider({

to something like:

if (!channelForClassifier) {
  console.error(
    "No classifier channel found",
    `classifier-${params.trainlabel}`,
  );
  return;
}

if (!channelForClassifier.nostrRoomEventId) {
  console.error(
    "Classifier channel has no nostrRoomEventId",
    channelForClassifier,
  );
  return;
}

const nostrProvider = new NostrProvider({
  ...
  nostrRoomCreateEventId:
    channelForClassifier.nostrRoomEventId,
  ...
});

Then fix the crypto contract.

Most importantly:
Your current log proves this:

["e", undefined]

is reaching the Nostr event serializer.

So fix nostrRoomEventId first.

Then fix encrypt/decrypt because those functions currently discard their asynchronous results and can corrupt the Yjs payload.

And don't chase the 32 KiB chunking code yet — the chunking code is not what is causing the wrong or missing properties error.



You said:

write the y-ndk file

ChatGPT said:
Below is a complete replacement y-ndk file based on your current implementation. It fixes the two issues we identified:

validates nostrRoomCreateEventId so ["e", undefined] can never be published
supports async encrypt/decrypt correctly
avoids the broken .then()/finally behavior
preserves legacy unchunked events
safely reassembles chunk batches
doesn't accidentally use an unrelated Nostr event as the room ID
adds provider cleanup
avoids publishing malformed events
keeps Yjs updates intact rather than slicing them
// y-ndk.js
//
// Nostr <-> Yjs synchronization.
//
// Yjs updates are structured binary data. We therefore NEVER split a single
// Yjs update by slicing bytes.
//
// Instead, multiple complete Yjs updates are merged into complete Yjs updates
// and those merged updates are used as Nostr chunks.
//
// Encryption/decryption may be synchronous OR asynchronous.
//
// Example:
//
//   encrypt: async (update) => {
//     ...
//     return encryptedBytes;
//   }
//
//   decrypt: async (bytes) => {
//     ...
//     return clearBytes;
//   }

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
 * Maximum raw Yjs bytes in one Nostr event.
 *
 * 32 KiB becomes approximately 43.7 KiB after base64 encoding.
 *
 * This leaves room for:
 *
 * - event JSON
 * - Nostr tags
 * - encryption overhead
 * - relay/proxy overhead
 */
const NOSTR_UPDATE_CHUNK_BYTES = 32 * 1024;

/**
 * How long incomplete chunk batches remain in memory.
 */
const CHUNK_BUFFER_MAX_AGE = 10 * 60 * 1000;

/**
 * Return the byte length of a binary value.
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

  throw new Error(
    "Unable to determine binary update size",
  );
}

/**
 * Convert binary-like values to Uint8Array.
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
 * Validate that a value is a usable Nostr event ID.
 */
function validateEventId(eventId, name = "event ID") {
  if (
    typeof eventId !== "string" ||
    eventId.length !== 64 ||
    !/^[0-9a-fA-F]+$/.test(eventId)
  ) {
    throw new Error(
      `Invalid ${name}: ${String(eventId)}`,
    );
  }

  return eventId;
}

/**
 * Split complete Yjs updates into conservative chunks.
 *
 * IMPORTANT:
 *
 * We do not slice individual Yjs updates.
 *
 * If an individual update is larger than the maximum, we throw rather than
 * corrupting it.
 */
function splitUpdatesIntoChunks(
  yjs,
  updates,
  maxBytes = NOSTR_UPDATE_CHUNK_BYTES,
) {
  const chunks = [];

  let current = [];
  let currentSize = 0;

  for (const rawUpdate of updates) {
    const update = toUint8Array(rawUpdate);
    const size = getByteLength(update);

    if (size > maxBytes) {
      throw new Error(
        `A single Yjs update is ${size} bytes, which exceeds ` +
          `${maxBytes} bytes. ` +
          `A Yjs update cannot safely be split by slicing bytes.`,
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
 * Create chunk metadata.
 *
 * ["chunk", batchId, index, total]
 */
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

/**
 * Publish a Nostr event.
 *
 * Supports:
 *
 * - NDK signing
 * - raw nostr-tools signing with a secret key
 */
async function publishEvent({
  ndk,
  explicitRelayUrls,
  secretNostrKey,
  eventTemplate,
}) {
  if (!eventTemplate) {
    throw new Error(
      "Cannot publish Nostr event without eventTemplate",
    );
  }

  if (
    !Number.isInteger(eventTemplate.kind)
  ) {
    throw new Error(
      "Cannot publish Nostr event: invalid kind",
    );
  }

  if (
    !Array.isArray(eventTemplate.tags)
  ) {
    throw new Error(
      "Cannot publish Nostr event: invalid tags",
    );
  }

  if (
    typeof eventTemplate.content !== "string"
  ) {
    throw new Error(
      "Cannot publish Nostr event: content must be a string",
    );
  }

  /**
   * Check for undefined/null tag values before handing the event to NDK.
   *
   * This catches things like:
   *
   * ["e", undefined]
   */
  for (const tag of eventTemplate.tags) {
    if (!Array.isArray(tag)) {
      throw new Error(
        "Cannot publish Nostr event: malformed tag",
      );
    }

    for (const value of tag) {
      if (
        value === undefined ||
        value === null
      ) {
        throw new Error(
          `Cannot publish Nostr event: tag contains ${String(value)}: ${JSON.stringify(tag)}`,
        );
      }
    }
  }

  if (secretNostrKey === undefined) {
    if (!ndk) {
      throw new Error(
        "Cannot publish Nostr event: missing NDK",
      );
    }

    const event = new NDKEvent(
      ndk,
      eventTemplate,
    );

    await event.publish();

    if (!event.id) {
      throw new Error(
        "Nostr event was published without an ID",
      );
    }

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

  if (
    !explicitRelayUrls ||
    explicitRelayUrls.length === 0
  ) {
    throw new Error(
      "Cannot publish signed Nostr event: no relay URLs",
    );
  }

  await pool.publish(
    explicitRelayUrls,
    signedEvent,
  );

  return signedEvent;
}

/**
 * Safely run a possibly synchronous or asynchronous function.
 */
async function resolveValue(value) {
  return await value;
}

/**
 * Create a Nostr CRDT room.
 *
 * The first initial-state chunk becomes the room creation event.
 *
 * Its event ID is the room ID.
 */
export async function createNostrCRDTRoom(
  params,
) {
  const {
    ndk,
    label,
    initialLocalState,
    YJS_UPDATE_EVENT_KIND,
    secretNostrKey,
    explicitRelayUrls,
    encrypt = async (input) => input,
    yjs,
  } = params;

  if (!ndk) {
    throw new Error(
      "createNostrCRDTRoom: missing ndk",
    );
  }

  if (!label) {
    throw new Error(
      "createNostrCRDTRoom: missing label",
    );
  }

  if (!Number.isInteger(YJS_UPDATE_EVENT_KIND)) {
    throw new Error(
      "createNostrCRDTRoom: invalid YJS_UPDATE_EVENT_KIND",
    );
  }

  if (!yjs) {
    /**
     * Compatibility path for callers that don't supply Yjs.
     */
    const encrypted =
      await resolveValue(
        encrypt(initialLocalState),
      );

    const event =
      await publishEvent({
        ndk,
        explicitRelayUrls,
        secretNostrKey,
        eventTemplate: {
          kind: YJS_UPDATE_EVENT_KIND,
          created_at: Math.floor(
            Date.now() / 1000,
          ),
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
      "Cannot create Nostr CRDT room from empty Yjs state",
    );
  }

  const batchId =
    crypto.randomUUID();

  const total =
    initialChunks.length;

  /**
   * First chunk becomes room creation event.
   */
  const firstChunk =
    initialChunks[0];

  const encryptedFirstChunk =
    await resolveValue(
      encrypt(firstChunk),
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
          Math.floor(
            Date.now() / 1000,
          ),

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
            encryptedFirstChunk,
          ),
        ),
      },
    });

  const roomId =
    validateEventId(
      firstEvent.id,
      "room event ID",
    );

  /**
   * Publish remaining initial-state chunks.
   */
  for (
    let i = 1;
    i < initialChunks.length;
    i++
  ) {
    const chunk =
      initialChunks[i];

    const encrypted =
      await resolveValue(
        encrypt(chunk),
      );

    await publishEvent({
      ndk,
      explicitRelayUrls,
      secretNostrKey,
      eventTemplate: {
        kind:
          YJS_UPDATE_EVENT_KIND,

        created_at:
          Math.floor(
            Date.now() / 1000,
          ),

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
      encrypt = async (input) => input,
      decrypt = async (input) => input,
    } = params;

    super();

    if (!yjs) {
      throw new Error(
        "NostrProvider: missing yjs",
      );
    }

    if (!ydoc) {
      throw new Error(
        "NostrProvider: missing ydoc",
      );
    }

    if (!ndk) {
      throw new Error(
        "NostrProvider: missing ndk",
      );
    }

    if (!Number.isInteger(YJS_UPDATE_EVENT_KIND)) {
      throw new Error(
        "NostrProvider: invalid YJS_UPDATE_EVENT_KIND",
      );
    }

    /**
     * This is deliberately strict.
     *
     * The bug you encountered was:
     *
     * ["e", undefined]
     */
    this.nostrRoomCreateEventId =
      validateEventId(
        nostrRoomCreateEventId,
        "nostrRoomCreateEventId",
      );

    this.yjs = yjs;
    this.ydoc = ydoc;
    this.ndk = ndk;

    this.YJS_UPDATE_EVENT_KIND =
      YJS_UPDATE_EVENT_KIND;

    this.secretNostrKey =
      secretNostrKey;

    this.explicitRelayUrls =
      explicitRelayUrls || [];

    this.encrypt = encrypt;
    this.decrypt = decrypt;

    /**
     * batchId -> {
     *
     *   total,
     *   chunks,
     *   received,
     *   createdAt
     *
     * }
     */
    this.chunkBuffer =
      new Map();

    this.chunkBufferMaxAge =
      CHUNK_BUFFER_MAX_AGE;

    this.pendingUpdates = [];

    this.sendPendingTimeout =
      undefined;

    this.destroyed = false;

    /**
     * Keep a reference so we can remove it during destroy().
     */
    this.documentUpdateHandler =
      (update, origin) => {
        this.documentUpdateListener(
          update,
          origin,
        );
      };

    this.ydoc.on(
      "update",
      this.documentUpdateHandler,
    );
  }

  /**
   * Encrypt one Yjs update.
   *
   * Supports synchronous and asynchronous crypto implementations.
   */
  async encryptUpdate(update) {
    const encrypted =
      await resolveValue(
        this.encrypt(
          toUint8Array(update),
        ),
      );

    return toUint8Array(
      encrypted,
    );
  }

  /**
   * Decrypt one Nostr event payload.
   */
  async decryptUpdate(content) {
    const encoded =
      fromBase64(content);

    const decrypted =
      await resolveValue(
        this.decrypt(encoded),
      );

    return toUint8Array(
      decrypted,
    );
  }

  /**
   * Convert Nostr events into one merged Yjs update.
   *
   * This method is asynchronous because encryption/decryption may be async.
   */
  async updateFromEvents(events) {
    const updates = [];

    for (const event of events) {
      try {
        const update =
          await this.decryptUpdate(
            event.content,
          );

        if (
          update &&
          update.length > 0
        ) {
          updates.push(update);
        }
      } catch (error) {
        console.error(
          "Failed to decode/decrypt Nostr Yjs event:",
          error,
        );
      }
    }

    if (updates.length === 0) {
      return undefined;
    }

    return this.yjs.mergeUpdates(
      updates,
    );
  }

  /**
   * Publish a single Yjs update.
   */
  async publishUpdate(update) {
    return this.publishUpdates([
      update,
    ]);
  }

  /**
   * Publish multiple Yjs updates.
   *
   * Complete Yjs updates are merged into conservative chunks.
   */
  async publishUpdates(updates) {
    if (
      this.destroyed ||
      !updates ||
      updates.length === 0
    ) {
      return;
    }

    /**
     * Never allow undefined room IDs into Nostr tags.
     */
    validateEventId(
      this.nostrRoomCreateEventId,
      "nostrRoomCreateEventId",
    );

    const chunks =
      splitUpdatesIntoChunks(
        this.yjs,
        updates,
        NOSTR_UPDATE_CHUNK_BYTES,
      );

    if (chunks.length === 0) {
      return;
    }

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

      const encrypted =
        await this.encryptUpdate(
          chunk,
        );

      const content =
        toBase64(
          encrypted,
        );

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

  /**
   * Queue a Yjs update for publication.
   */
  async documentUpdateListener(
    update,
    origin,
  ) {
    if (this.destroyed) {
      return;
    }

    /**
     * Do not rebroadcast updates that originated from this provider.
     */
    if (origin === this) {
      return;
    }

    /**
     * Do not rebroadcast updates originating from another provider.
     */
    if (origin?.provider) {
      return;
    }

    this.pendingUpdates.push(
      update,
    );

    if (
      this.sendPendingTimeout !==
      undefined
    ) {
      clearTimeout(
        this.sendPendingTimeout,
      );
    }

    this.sendPendingTimeout =
      setTimeout(
        async () => {
          this.sendPendingTimeout =
            undefined;

          if (this.destroyed) {
            return;
          }

          const updates =
            this.pendingUpdates;

          this.pendingUpdates = [];

          try {
            await this.publishUpdates(
              updates,
            );
          } catch (error) {
            console.error(
              "Failed to publish Yjs update:",
              error,
            );

            /**
             * Put failed updates back at the front.
             */
            this.pendingUpdates.unshift(
              ...updates,
            );
          }
        },
        100,
      );
  }

  /**
   * Remove stale incomplete batches.
   */
  cleanupChunkBuffer() {
    const now =
      Date.now();

    for (
      const [
        batchId,
        batch,
      ] of this.chunkBuffer
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
  async processIncomingEvent(
    event,
  ) {
    if (
      this.destroyed ||
      !event
    ) {
      return;
    }

    const chunkTag =
      event.tags?.find(
        (tag) =>
          tag?.[0] === "chunk",
      );

    /**
     * Legacy event.
     */
    if (!chunkTag) {
      try {
        const update =
          await this.decryptUpdate(
            event.content,
          );

        if (
          !update ||
          update.length === 0
        ) {
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

    /**
     * Don't accept chunks claiming a different total.
     */
    if (
      batch.total !== total
    ) {
      console.warn(
        "Ignoring chunk with mismatched total:",
        chunkTag,
      );

      return;
    }

    /**
     * Duplicate chunk.
     */
    if (
      batch.chunks[index] !==
      undefined
    ) {
      return;
    }

    let update;

    try {
      update =
        await this.decryptUpdate(
          event.content,
        );
    } catch (error) {
      console.error(
        "Failed to decode/decrypt incoming Yjs chunk:",
        error,
      );

      return;
    }

    if (
      !update ||
      update.length === 0
    ) {
      console.warn(
        "Ignoring empty Yjs chunk:",
        chunkTag,
      );

      return;
    }

    batch.chunks[index] =
      update;

    batch.received++;

    /**
     * Wait until every chunk arrives.
     */
    if (
      batch.received !==
      batch.total
    ) {
      return;
    }

    /**
     * Verify every position exists.
     */
    for (
      let i = 0;
      i < batch.total;
      i++
    ) {
      if (
        batch.chunks[i] ===
        undefined
      ) {
        console.warn(
          "Chunk batch reported complete but has missing chunk:",
          {
            batchId,
            index: i,
            total: batch.total,
          },
        );

        return;
      }
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
        },
      );

      /**
       * The chunks themselves are complete Yjs updates.
       *
       * mergeUpdates() reconstructs one valid update.
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

      this.chunkBuffer.delete(
        batchId,
      );
    }
  }

  /**
   * Process multiple events.
   */
  async processIncomingEvents(
    events,
  ) {
    if (
      !events ||
      events.length === 0
    ) {
      return;
    }

    for (const event of events) {
      await this.processIncomingEvent(
        event,
      );
    }
  }

  /**
   * Reassemble complete historical chunk batches.
   *
   * Incomplete batches are omitted.
   */
  updateFromInitialEvents(
    events,
  ) {
    const completeEvents =
      [];

    const batches =
      new Map();

    for (const event of events) {
      const chunkTag =
        event.tags?.find(
          (tag) =>
            tag?.[0] === "chunk",
        );

      /**
       * Legacy unchunked event.
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

    /**
     * Only return complete batches.
     */
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

      let complete =
        true;

      for (
        let i = 0;
        i < batch.total;
        i++
      ) {
        if (
          batch.events[i] ===
          undefined
        ) {
          complete = false;
          break;
        }
      }

      if (!complete) {
        continue;
      }

      /**
       * Sort by chunk index.
       */
      completeEvents.push(
        ...batch.events,
      );
    }

    return completeEvents;
  }

  /**
   * Initialize the provider.
   */
  async initialize() {
    if (this.destroyed) {
      return;
    }

    try {
      let eoseSeen =
        false;

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

      this.subscription =
        sub;

      sub.on(
        "event",
        (event) => {
          if (
            this.destroyed
          ) {
            return;
          }

          if (!eoseSeen) {
            initialEvents.push(
              event,
            );
          } else {
            this.processIncomingEvent(
              event,
            ).catch(
              (error) => {
                console.error(
                  "Failed to process incoming Nostr event:",
                  error,
                );
              },
            );
          }
        },
      );

      sub.on(
        "events",
        (events) => {
          if (
            this.destroyed
          ) {
            return;
          }

          if (eoseSeen) {
            this.processIncomingEvents(
              events,
            ).catch(
              (error) => {
                console.error(
                  "Failed to process incoming Nostr events:",
                  error,
                );
              },
            );
          }
        },
      );

      sub.on(
        "eose",
        () => {
          if (
            this.destroyed ||
            eoseSeen
          ) {
            return;
          }

          eoseSeen = true;

          this.handleInitialEvents(
            initialEvents,
          ).catch(
            (error) => {
              console.error(
                "Failed to initialize Yjs from Nostr:",
                error,
              );
            },
          );
        },
      );
    } catch (error) {
      console.error(
        "NostrProvider initialization failed:",
        error,
      );

      throw error;
    }
  }

  /**
   * Handle initial remote history after EOSE.
   */
  async handleInitialEvents(
    initialEvents,
  ) {
    if (this.destroyed) {
      return;
    }

    /**
     * Reassemble complete historical batches.
     */
    const usableInitialEvents =
      this.updateFromInitialEvents(
        initialEvents,
      );

    /**
     * Capture local state BEFORE applying remote state.
     */
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

    let remoteUpdate;

    /**
     * Apply remote history.
     */
    if (
      usableInitialEvents.length >
      0
    ) {
      remoteUpdate =
        await this.updateFromEvents(
          usableInitialEvents,
        );

      if (
        remoteUpdate !==
        undefined
      ) {
        this.yjs.applyUpdate(
          this.ydoc,
          remoteUpdate,
          this,
        );
      }
    }

    /**
     * No remote state exists.
     *
     * Publish local state.
     */
    if (
      usableInitialEvents.length ===
        0 ||
      remoteUpdate === undefined
    ) {
      const localUpdate =
        this.yjs.encodeStateAsUpdate(
          this.ydoc,
        );

      if (
        localUpdate.length > 2
      ) {
        await this.publishUpdates([
          localUpdate,
        ]);
      }

      return;
    }

    /**
     * Determine which local changes aren't on the server.
     */
    const remoteStateVector =
      this.yjs.encodeStateVectorFromUpdate(
        remoteUpdate,
      );

    const missingOnWire =
      this.yjs.diffUpdate(
        initialLocalState,
        remoteStateVector,
      );

    /**
     * Preserve the existing delete-set safety check.
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
        remoteUpdate,
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
         * missingOnWire only represents deletes already represented
         * by the server.
         */
      }
    }

    /**
     * Publish local changes that weren't present remotely.
     */
    if (
      missingOnWire.length > 2
    ) {
      await this.publishUpdates([
        missingOnWire,
      ]);
    }
  }

  /**
   * Stop synchronization and remove listeners.
   */
  destroy() {
    if (this.destroyed) {
      return;
    }

    this.destroyed = true;

    if (
      this.sendPendingTimeout !==
      undefined
    ) {
      clearTimeout(
        this.sendPendingTimeout,
      );

      this.sendPendingTimeout =
        undefined;
    }

    /**
     * Remove Yjs listener.
     */
    if (
      this.ydoc &&
      this.documentUpdateHandler
    ) {
      this.ydoc.off(
        "update",
        this.documentUpdateHandler,
      );
    }

    /**
     * Close NDK subscription.
     */
    try {
      this.subscription?.stop?.();
    } catch (error) {
      console.warn(
        "Failed to stop Nostr subscription:",
        error,
      );
    }

    try {
      this.subscription?.close?.();
    } catch (error) {
      console.warn(
        "Failed to close Nostr subscription:",
        error,
      );
    }

    this.subscription =
      undefined;

    this.pendingUpdates = [];

    this.chunkBuffer.clear();

    this.destroy?.();
  }
}
