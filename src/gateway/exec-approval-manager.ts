import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { ExecApprovalDecision } from "../infra/exec-approvals.js";

// Grace period to keep resolved entries for late awaitDecision calls
const RESOLVED_ENTRY_GRACE_MS = 15_000;

const JOURNAL_FILENAME = "exec-approval-journal.jsonl";

export type ExecApprovalRequestPayload = {
  command: string;
  cwd?: string | null;
  host?: string | null;
  security?: string | null;
  ask?: string | null;
  agentId?: string | null;
  resolvedPath?: string | null;
  sessionKey?: string | null;
};

export type ExecApprovalRecord = {
  id: string;
  request: ExecApprovalRequestPayload;
  createdAtMs: number;
  expiresAtMs: number;
  // Caller metadata (best-effort). Used to prevent other clients from replaying an approval id.
  requestedByConnId?: string | null;
  requestedByDeviceId?: string | null;
  requestedByClientId?: string | null;
  resolvedAtMs?: number;
  decision?: ExecApprovalDecision;
  resolvedBy?: string | null;
};

export type JournalEntry = {
  id: string;
  command: string;
  decision: ExecApprovalDecision | undefined;
  resolvedBy: string | null;
  resolvedAtMs: number;
  requestedByDeviceId?: string | null;
};

type PendingEntry = {
  record: ExecApprovalRecord;
  resolve: (decision: ExecApprovalDecision | null) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  promise: Promise<ExecApprovalDecision | null>;
};

export class ExecApprovalManager {
  private pending = new Map<string, PendingEntry>();
  private readonly persistDir: string | undefined;

  constructor(opts?: { persistDir?: string }) {
    this.persistDir = opts?.persistDir;
  }

  private get journalPath(): string | undefined {
    return this.persistDir ? path.join(this.persistDir, JOURNAL_FILENAME) : undefined;
  }

  create(
    request: ExecApprovalRequestPayload,
    timeoutMs: number,
    id?: string | null,
  ): ExecApprovalRecord {
    const now = Date.now();
    const resolvedId = id && id.trim().length > 0 ? id.trim() : randomUUID();
    const record: ExecApprovalRecord = {
      id: resolvedId,
      request,
      createdAtMs: now,
      expiresAtMs: now + timeoutMs,
    };
    return record;
  }

  /**
   * Register an approval record and return a promise that resolves when the decision is made.
   * This separates registration (synchronous) from waiting (async), allowing callers to
   * confirm registration before the decision is made.
   */
  register(record: ExecApprovalRecord, timeoutMs: number): Promise<ExecApprovalDecision | null> {
    const existing = this.pending.get(record.id);
    if (existing) {
      // Idempotent: return existing promise if still pending
      if (existing.record.resolvedAtMs === undefined) {
        return existing.promise;
      }
      // Already resolved - don't allow re-registration
      throw new Error(`approval id '${record.id}' already resolved`);
    }
    let resolvePromise: (decision: ExecApprovalDecision | null) => void;
    let rejectPromise: (err: Error) => void;
    const promise = new Promise<ExecApprovalDecision | null>((resolve, reject) => {
      resolvePromise = resolve;
      rejectPromise = reject;
    });
    // Create entry first so we can capture it in the closure (not re-fetch from map)
    const entry: PendingEntry = {
      record,
      resolve: resolvePromise!,
      reject: rejectPromise!,
      timer: null as unknown as ReturnType<typeof setTimeout>,
      promise,
    };
    entry.timer = setTimeout(() => {
      // Update snapshot fields before resolving (mirror resolve()'s bookkeeping)
      record.resolvedAtMs = Date.now();
      record.decision = undefined;
      record.resolvedBy = null;
      resolvePromise(null);
      // Keep entry briefly for in-flight awaitDecision calls
      setTimeout(() => {
        // Compare against captured entry instance, not re-fetched from map
        if (this.pending.get(record.id) === entry) {
          this.pending.delete(record.id);
        }
      }, RESOLVED_ENTRY_GRACE_MS);
    }, timeoutMs);
    this.pending.set(record.id, entry);
    return promise;
  }

  /**
   * @deprecated Use register() instead for explicit separation of registration and waiting.
   */
  async waitForDecision(
    record: ExecApprovalRecord,
    timeoutMs: number,
  ): Promise<ExecApprovalDecision | null> {
    return this.register(record, timeoutMs);
  }

  resolve(recordId: string, decision: ExecApprovalDecision, resolvedBy?: string | null): boolean {
    const pending = this.pending.get(recordId);
    if (!pending) {
      return false;
    }
    // Prevent double-resolve (e.g., if called after timeout already resolved)
    if (pending.record.resolvedAtMs !== undefined) {
      return false;
    }
    clearTimeout(pending.timer);
    pending.record.resolvedAtMs = Date.now();
    pending.record.decision = decision;
    pending.record.resolvedBy = resolvedBy ?? null;
    // Persist to journal (best-effort, never blocks resolve)
    this.appendJournalEntry(pending.record);
    // Resolve the promise first, then delete after a grace period.
    // This allows in-flight awaitDecision calls to find the resolved entry.
    pending.resolve(decision);
    setTimeout(() => {
      // Only delete if the entry hasn't been replaced
      if (this.pending.get(recordId) === pending) {
        this.pending.delete(recordId);
      }
    }, RESOLVED_ENTRY_GRACE_MS);
    return true;
  }

  getSnapshot(recordId: string): ExecApprovalRecord | null {
    const entry = this.pending.get(recordId);
    return entry?.record ?? null;
  }

  /**
   * Wait for decision on an already-registered approval.
   * Returns the decision promise if the ID is pending, null otherwise.
   */
  awaitDecision(recordId: string): Promise<ExecApprovalDecision | null> | null {
    const entry = this.pending.get(recordId);
    return entry?.promise ?? null;
  }

  /**
   * Load the audit journal from disk. Returns parsed entries.
   */
  loadJournal(): JournalEntry[] {
    const journalPath = this.journalPath;
    if (!journalPath) {
      return [];
    }
    try {
      const content = fs.readFileSync(journalPath, "utf-8");
      const entries: JournalEntry[] = [];
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          entries.push(JSON.parse(trimmed) as JournalEntry);
        } catch {
          // skip malformed lines
        }
      }
      return entries;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return [];
      }
      throw err;
    }
  }

  /**
   * Returns recent resolved approvals from the journal.
   */
  getAuditLog(limit?: number): JournalEntry[] {
    const entries = this.loadJournal();
    if (limit !== undefined && limit > 0) {
      return entries.slice(-limit);
    }
    return entries;
  }

  private appendJournalEntry(record: ExecApprovalRecord): void {
    const journalPath = this.journalPath;
    if (!journalPath) {
      return;
    }
    const entry: JournalEntry = {
      id: record.id,
      command: record.request.command,
      decision: record.decision,
      resolvedBy: record.resolvedBy ?? null,
      resolvedAtMs: record.resolvedAtMs!,
      requestedByDeviceId: record.requestedByDeviceId ?? null,
    };
    try {
      fs.mkdirSync(path.dirname(journalPath), { recursive: true });
      fs.appendFileSync(journalPath, JSON.stringify(entry) + "\n", {
        encoding: "utf-8",
        mode: 0o600,
      });
    } catch {
      // best-effort: never block resolve on journal write failure
    }
  }
}
