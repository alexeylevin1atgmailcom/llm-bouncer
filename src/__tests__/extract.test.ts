import { describe, it, expect } from "vitest";
import { autoExtract } from "../middleware/extract.js";

describe("autoExtract", () => {
  it("extracts 'message' field", () => {
    expect(autoExtract({ message: "hello" })).toBe("hello");
  });

  it("extracts 'prompt' field", () => {
    expect(autoExtract({ prompt: "tell me" })).toBe("tell me");
  });

  it("extracts 'input' field", () => {
    expect(autoExtract({ input: "my input" })).toBe("my input");
  });

  it("extracts last user message from messages array", () => {
    const body = {
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: "Hello!" },
        { role: "assistant", content: "Hi there!" },
        { role: "user", content: "What is 2+2?" },
      ],
    };
    expect(autoExtract(body)).toBe("What is 2+2?");
  });

  it("skips system message when looking for last user message", () => {
    const body = {
      messages: [
        { role: "system", content: "System instructions." },
        { role: "user", content: "User message." },
      ],
    };
    expect(autoExtract(body)).toBe("User message.");
  });

  it("returns undefined for null", () => {
    expect(autoExtract(null)).toBeUndefined();
  });

  it("returns undefined for empty body", () => {
    expect(autoExtract({})).toBeUndefined();
  });

  it("returns undefined for non-object", () => {
    expect(autoExtract("raw string")).toBeUndefined();
  });

  it("returns undefined when all relevant fields are empty strings", () => {
    expect(autoExtract({ message: "  " })).toBeUndefined();
  });
});
