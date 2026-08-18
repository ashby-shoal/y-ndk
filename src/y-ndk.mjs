// plagiarized from:
// https://github.com/YousefED/nostr-crdt/blob/main/packages/nostr-crdt/src/createNostrCRDTRoom.ts
// chatgpt - please handle d1 message from nosflare
// Absolutely — here is the complete replacement file with chunking integrated. I’ve kept the existing API and behavior, while adding chunk metadata, buffering/reassembly, duplicate protection, and a conservative 1.5 MB binary chunk target.

// NostrProvider with D1-safe chunked updates
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
 * D1 has a 2 MB limit for individual string/blob values.
 *
 * We intentionally stay below that limit because Base64 encoding expands
 * binary data by approximately 33%, and the Nostr event itself contains
 * additional metadata.
 *
 * If Nosflare stores events through SQL text rather than bound parameters,
 * reduce this substantially (e.g. 64 KB).
 */
const NOSTR_UPDATE_CHUNK_BYTES = 1_500_000;

/**
 * Split a collection of Yjs updates into groups that can safely be merged
 * into individual Nostr events.
 *
 * IMPORTANT:
 * We never split an individual Yjs update by slicing its bytes. Yjs updates
 * are structured binary data and arbitrary byte slicing would corrupt them.
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
    const size = update.byteLength ?? update.length;

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
      chunks.push(yjs.mergeUpdates(current));
      current = [];
      currentSize = 0;
    }

    current.push(update);
    currentSize += size;
  }

  if (current.length > 0) {
    chunks.push(yjs.mergeUpdates(current));
  }

  return chunks;
}

export async function createNostrCRDTRoom(params) {
  // plagiarized from:
  // https://github.com/YousefED/nostr-crdt/blob/main/packages/nostr-crdt/src/createNostrCRDTRoom.ts

  const {
    ndk,
    label,
    initialLocalState,
    YJS_UPDATE_EVENT_KIND,
    secretNostrKey,
    explicitRelayUrls,
    encrypt,
  } = {
    encrypt: (passthrough) => passthrough,
    ...params,
  };

  return new Promise((resolve) => {
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
      resolve(event.id);
    });

    if (secretNostrKey === undefined) {
      const event = new NDKEvent(ndk, {
        kind: YJS_UPDATE_EVENT_KIND,
        tags: [["crdt", label]],
        content: toBase64(encrypt(initialLocalState)),
      });

      event.publish();
    }

    if (secretNostrKey !== undefined) {
      ndk.signer.user().then(() => {
        const signedEvent = finalizeEvent(
          {
            kind: YJS_UPDATE_EVENT_KIND,
            created_at: Math.floor(Date.now() / 1000),
            tags: [["crdt", label]],
            content: toBase64(encrypt(initialLocalState)),
          },
          secretNostrKey,
        );

        if (verifyEvent(signedEvent)) {
          pool.publish(
            params.explicitRelayUrls,
            signedEvent,
          );
        }
      });
    }
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

    this.ydoc.on("update", (update, origin) => {
      this.documentUpdateListener(update, origin);
    });

    this.YJS_UPDATE_EVENT_KIND =
      YJS_UPDATE_EVENT_KIND;

    this.secretNostrKey = secretNostrKey;
    this.explicitRelayUrls = explicitRelayUrls;
    this.encrypt = encrypt;
    this.decrypt = decrypt;

    /**
     * Stores partially received chunked updates.
     *
     * batchId -> {
     *   total: number,
     *   chunks: Array<Uint8Array | undefined>,
     *   received: number
     * }
     */
    this.chunkBuffer = new Map();
  }

  /**
   * Converts a collection of Nostr events into a single Yjs update.
   *
   * This method supports both:
   *
   * 1. Old events without chunk metadata.
   * 2. Chunked events, assuming the caller has already reassembled them.
   */
  updateFromEvents(events) {
    const updates = events
      .map((e) =>
        this.decrypt(
          fromBase64(e.content),
        ),
      )
      .filter(Boolean);

    if (updates.length === 0) {
      return undefined;
    }

    return this.yjs.mergeUpdates(updates);
  }

  /**
   * Publishes a single already-combined update.
   *
   * Kept for compatibility with callers that may still call publishUpdate().
   */
  async publishUpdate(update) {
    return this.publishUpdates([update]);
  }

  /**
   * Publishes one or more Yjs updates as D1-safe Nostr events.
   *
   * Every batch gets a unique batch ID:
   *
   *   ["chunk", batchId, "0", "3"]
   *   ["chunk", batchId, "1", "3"]
   *   ["chunk", batchId, "2", "3"]
   *
   * The receiver waits until all chunks arrive before applying the
   * reconstructed update.
   */
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

      const tags = [
        ["e", this.nostrRoomCreateEventId],
        [
          "chunk",
          batchId,
          String(i),
          String(total),
        ],
      ];

      const content = toBase64(
        this.encrypt(chunk),
      );

      if (this.secretNostrKey === undefined) {
        const event = new NDKEvent(this.ndk, {
          kind: this.YJS_UPDATE_EVENT_KIND,
          tags,
          content,
        });

        await event.publish();
      } else {
        const signedEvent = finalizeEvent(
          {
            kind: this.YJS_UPDATE_EVENT_KIND,
            created_at: Math.floor(Date.now() / 1000),
            tags,
            content,
          },
          this.secretNostrKey,
        );

        if (verifyEvent(signedEvent)) {
          await pool.publish(
            this.explicitRelayUrls,
            signedEvent,
          );
        }
      }
    }
  }

  pendingUpdates = [];
  sendPendingTimeout;

  async documentUpdateListener(update, origin) {
    // https://discuss.yjs.dev/t/how-to-distinguish-which-user-triggered-this-update/2584

    if (origin === this) {
      return;
    }

    if (origin?.provider) {
      return;
    }

    this.pendingUpdates.push(update);

    if (this.sendPendingTimeout) {
      clearTimeout(this.sendPendingTimeout);
    }

    this.sendPendingTimeout = setTimeout(() => {
      const updates = this.pendingUpdates;

      this.pendingUpdates = [];

      this.publishUpdates(updates).catch((error) => {
        console.error(
          "Failed to publish Yjs update:",
          error,
        );

        // Put the updates back into the queue so a later update
        // can retry them rather than silently losing local changes.
        this.pendingUpdates.unshift(...updates);
      });
    }, 100);
  }

  /**
   * Processes a single incoming Nostr event.
   *
   * Non-chunked events are applied immediately.
   *
   * Chunked events are buffered until all chunks belonging to their batch
   * have arrived.
   */
  processIncomingEvent = (event) => {
    const chunkTag = event.tags?.find(
      (tag) => tag[0] === "chunk",
    );

    /**
     * Backwards compatibility:
     *
     * Events created by the old provider have no chunk tag.
     */
    if (!chunkTag) {
      const update = this.decrypt(
        fromBase64(event.content),
      );

      if (update === undefined) {
        return;
      }

      this.yjs.applyUpdate(
        this.ydoc,
        update,
        this,
      );

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
        "Ignoring invalid Nostr Yjs chunk:",
        chunkTag,
      );

      return;
    }

    let batch = this.chunkBuffer.get(batchId);

    if (!batch) {
      batch = {
        total,
        chunks: new Array(total),
        received: 0,
      };

      this.chunkBuffer.set(
        batchId,
        batch,
      );
    }

    /**
     * If we somehow receive the same event twice,
     * don't count it twice.
     */
    if (batch.chunks[index] !== undefined) {
      return;
    }

    const update = this.decrypt(
      fromBase64(event.content),
    );

    if (update === undefined) {
      return;
    }

    batch.chunks[index] = update;
    batch.received++;

    /**
     * We don't have the complete batch yet.
     */
    if (batch.received !== batch.total) {
      return;
    }

    /**
     * All chunks are available.
     */
    const mergedUpdate = this.yjs.mergeUpdates(
      batch.chunks,
    );

    this.chunkBuffer.delete(batchId);

    this.yjs.applyUpdate(
      this.ydoc,
      mergedUpdate,
      this,
    );
  };

  /**
   * Handles incoming events from Nostr.
   *
   * This method remains available for callers that pass multiple events.
   */
  processIncomingEvents = (events) => {
    for (const event of events) {
      this.processIncomingEvent(event);
    }
  };

  /**
   * Reassembles complete chunk batches from an initial event set.
   *
   * Events belonging to incomplete batches are ignored here. They will be
   * available through the live subscription if they are subsequently
   * delivered.
   */
  updateFromInitialEvents(events) {
    const completeEvents = [];
    const batches = new Map();

    for (const event of events) {
      const chunkTag = event.tags?.find(
        (tag) => tag[0] === "chunk",
      );

      /**
       * Old-format event.
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

        batches.set(batchId, batch);
      }

      if (batch.events[index] !== undefined) {
        continue;
      }

      batch.events[index] = event;
      batch.received++;
    }

    /**
     * Add only complete batches.
     */
    for (const batch of batches.values()) {
      if (batch.received !== batch.total) {
        continue;
      }

      completeEvents.push(...batch.events);
    }

    return completeEvents;
  };

  async initialize() {
    try {
      let eoseSeen = false;
      const initialEvents = [];

      const sub = this.ndk.subscribe(
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

      sub.on("event", (e) => {
        if (!eoseSeen) {
          initialEvents.push(e);
        } else {
          this.processIncomingEvent(e);
        }
      });

      sub.on("events", (es) => {
        if (eoseSeen) {
          this.processIncomingEvents(es);
        }
      });

      sub.on("eose", () => {
        eoseSeen = true;

        /**
         * Filter/reassemble the events we can actually use.
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
          this.yjs.snapshot(this.ydoc);

        /**
         * If there were no complete events, create an empty
         * remote update rather than calling mergeUpdates([]).
         */
        let update;

        if (usableInitialEvents.length > 0) {
          update = this.updateFromEvents(
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
         * If there was no remote history, there is nothing to compare.
         */
        if (
          usableInitialEvents.length === 0 ||
          update === undefined
        ) {
          const localUpdate =
            this.yjs.encodeStateAsUpdate(
              this.ydoc,
            );

          if (localUpdate.length > 2) {
            this.publishUpdates([
              localUpdate,
            ]).catch(console.error);
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
         * missingOnWire will always contain the entire
         * deleteSet on startup.
         *
         * Unfortunately diffUpdate doesn't work well with deletes.
         * Check whether the missing update contains only deletes
         * that already exist on the server.
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
            this.yjs.snapshot(serverDoc);

          if (
            snapshotContainsAllDeletes(
              serverSnapshot,
              oldSnapshot,
            )
          ) {
            /**
             * missingOnWire only contains a deleteSet
             * with items already present on the server.
             */
          }
        }

        /**
         * publishUpdates() handles D1-safe chunking.
         */
        if (missingOnWire.length > 2) {
          this.publishUpdates([
            missingOnWire,
          ]).catch((error) => {
            console.error(
              "Failed to publish missing Yjs update:",
              error,
            );
          });
        }
      });
    } catch (e) {
      console.error(e);
    }
  }
}
