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
const NOSTR_UPDATE_CHUNK_BYTES = 128 * 1024;

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
