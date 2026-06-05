/**
 * Auto-extractor — pulls the user's chat text out of common request body shapes.
 * Covers: { message }, { prompt }, { input }, { messages: [...] }
 */

export function autoExtract(body: unknown): string | undefined {
  if (body == null || typeof body !== "object") return undefined;
  const b = body as Record<string, unknown>;

  // Simple top-level fields
  for (const key of ["message", "prompt", "input", "content", "text", "query"]) {
    const val = b[key];
    if (typeof val === "string" && val.trim()) return val;
  }

  // OpenAI-style: messages array — take the last user message
  const messages = b["messages"];
  if (Array.isArray(messages) && messages.length > 0) {
    // Walk from end to find the last user message.
    for (let i = messages.length - 1; i >= 0; i--) {
      const msg = messages[i];
      if (
        msg != null &&
        typeof msg === "object" &&
        ("role" in msg ? (msg as Record<string, unknown>)["role"] !== "system" : true)
      ) {
        const content = (msg as Record<string, unknown>)["content"];
        if (typeof content === "string" && content.trim()) return content;
      }
    }
  }

  return undefined;
}
