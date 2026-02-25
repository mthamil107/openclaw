import { describe, expect, it } from "vitest";
import { pickErrorFromPayloads } from "./helpers.js";

describe("pickErrorFromPayloads", () => {
  it("returns undefined when no payloads have errors", () => {
    expect(pickErrorFromPayloads([])).toBeUndefined();
    expect(pickErrorFromPayloads([{ text: "hello" }])).toBeUndefined();
    expect(pickErrorFromPayloads([{ text: "hello", isError: false }])).toBeUndefined();
  });

  it("returns error text when a payload has isError: true", () => {
    const payloads = [{ text: "HTTP 403 Forbidden", isError: true }];
    expect(pickErrorFromPayloads(payloads)).toBe("HTTP 403 Forbidden");
  });

  it("concatenates multiple error payloads with semicolons", () => {
    const payloads = [
      { text: "Error 1", isError: true },
      { text: "OK response" },
      { text: "Error 2", isError: true },
    ];
    expect(pickErrorFromPayloads(payloads)).toBe("Error 1; Error 2");
  });

  it("ignores error payloads without text", () => {
    const payloads = [
      { isError: true },
      { text: "", isError: true },
      { text: "real error", isError: true },
    ];
    expect(pickErrorFromPayloads(payloads)).toBe("real error");
  });
});
