import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { ExecApprovalManager } from "./exec-approval-manager.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = path.join(os.tmpdir(), `exec-approval-test-${randomUUID()}`);
  fs.mkdirSync(dir, { recursive: true });
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore cleanup failures
    }
  }
});

describe("ExecApprovalManager journal persistence", () => {
  it("writes journal entry on resolve", () => {
    const persistDir = makeTempDir();
    const manager = new ExecApprovalManager({ persistDir });
    const record = manager.create({ command: "echo hello" }, 30_000);
    manager.register(record, 30_000);
    manager.resolve(record.id, "approve", "test-user");

    const journalPath = path.join(persistDir, "exec-approval-journal.jsonl");
    expect(fs.existsSync(journalPath)).toBe(true);

    const content = fs.readFileSync(journalPath, "utf-8").trim();
    const entry = JSON.parse(content);
    expect(entry.id).toBe(record.id);
    expect(entry.command).toBe("echo hello");
    expect(entry.decision).toBe("approve");
    expect(entry.resolvedBy).toBe("test-user");
    expect(typeof entry.resolvedAtMs).toBe("number");
  });

  it("journal survives manager recreation (simulating restart)", () => {
    const persistDir = makeTempDir();

    // First manager instance: create and resolve an approval
    const manager1 = new ExecApprovalManager({ persistDir });
    const record1 = manager1.create({ command: "ls -la" }, 30_000);
    manager1.register(record1, 30_000);
    manager1.resolve(record1.id, "approve", "user-1");

    // Second manager instance: simulate gateway restart
    const manager2 = new ExecApprovalManager({ persistDir });
    const journal = manager2.loadJournal();

    expect(journal).toHaveLength(1);
    expect(journal[0].id).toBe(record1.id);
    expect(journal[0].command).toBe("ls -la");
    expect(journal[0].decision).toBe("approve");
    expect(journal[0].resolvedBy).toBe("user-1");
  });

  it("appends multiple entries to journal", () => {
    const persistDir = makeTempDir();
    const manager = new ExecApprovalManager({ persistDir });

    const record1 = manager.create({ command: "cmd1" }, 30_000);
    manager.register(record1, 30_000);
    manager.resolve(record1.id, "approve", "user-a");

    const record2 = manager.create({ command: "cmd2" }, 30_000);
    manager.register(record2, 30_000);
    manager.resolve(record2.id, "deny", "user-b");

    const log = manager.getAuditLog();
    expect(log).toHaveLength(2);
    expect(log[0].command).toBe("cmd1");
    expect(log[0].decision).toBe("approve");
    expect(log[1].command).toBe("cmd2");
    expect(log[1].decision).toBe("deny");
  });

  it("getAuditLog respects limit parameter", () => {
    const persistDir = makeTempDir();
    const manager = new ExecApprovalManager({ persistDir });

    for (let i = 0; i < 5; i++) {
      const record = manager.create({ command: `cmd-${i}` }, 30_000);
      manager.register(record, 30_000);
      manager.resolve(record.id, "approve");
    }

    const limited = manager.getAuditLog(2);
    expect(limited).toHaveLength(2);
    expect(limited[0].command).toBe("cmd-3");
    expect(limited[1].command).toBe("cmd-4");
  });

  it("journal file has restricted permissions", () => {
    if (process.platform === "win32") {
      // File permission checks are not reliable on Windows
      return;
    }
    const persistDir = makeTempDir();
    const manager = new ExecApprovalManager({ persistDir });
    const record = manager.create({ command: "secret-cmd" }, 30_000);
    manager.register(record, 30_000);
    manager.resolve(record.id, "approve");

    const journalPath = path.join(persistDir, "exec-approval-journal.jsonl");
    const stat = fs.statSync(journalPath);
    // 0o600 = owner read/write only
    const mode = stat.mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("works without persistDir (no journal)", () => {
    const manager = new ExecApprovalManager();
    const record = manager.create({ command: "echo test" }, 30_000);
    manager.register(record, 30_000);
    const resolved = manager.resolve(record.id, "approve");

    expect(resolved).toBe(true);
    expect(manager.loadJournal()).toEqual([]);
    expect(manager.getAuditLog()).toEqual([]);
  });
});
