import { consume } from "@lit/context";
import { LitElement, html } from "lit";
import { customElement, state } from "lit/decorators.js";
import { gatewayContext } from "../context/gateway-context.js";

type ChatEventPayload = {
  runId?: string;
  state?: string;
  delta?: string;
  text?: string;
};

@customElement("chat-view")
export class ChatView extends LitElement {
  @consume({ context: gatewayContext, subscribe: true })
  gateway!: import("../context/gateway-context.js").GatewayState;

  override createRenderRoot() {
    return this;
  }

  @state() sessionKey = "main";
  @state() message = "";
  @state() submitting = false;
  @state() logLines: string[] = [];

  private get latestChatEvent(): ChatEventPayload | null {
    const ev = this.gateway?.lastEvent;
    if (!ev || ev.event !== "chat") {
      return null;
    }
    return (ev.payload as ChatEventPayload | undefined) ?? null;
  }

  private async onSend(): Promise<void> {
    const trimmed = this.message.trim();
    if (!trimmed || this.submitting || !this.gateway) {
      return;
    }
    this.submitting = true;
    this.logLines = [`You: ${trimmed}`, ...this.logLines].slice(0, 120);
    this.message = "";
    try {
      await this.gateway.request("chat.send", {
        sessionKey: this.sessionKey,
        message: trimmed,
      });
    } catch (error) {
      const text = error instanceof Error ? error.message : String(error);
      this.logLines = [`Error: ${text}`, ...this.logLines].slice(0, 120);
    } finally {
      this.submitting = false;
    }
  }

  private handleKeyDown = (e: KeyboardEvent): void => {
    if (e.key === "Enter") {
      void this.onSend();
    }
  };

  override render() {
    const g = this.gateway;
    if (!g) {
      return html`
        <p class="muted">Loading...</p>
      `;
    }

    const latest = this.latestChatEvent;

    return html`
      <section class="panel">
        <h2>Chat</h2>
        <p class="muted">
          Minimal phase-1 chat path. Uses existing gateway method/event flow without introducing new
          privileged API surfaces.
        </p>

        <div class="input-row">
          <input
            .value=${this.sessionKey}
            @input=${(e: Event) => {
              this.sessionKey = (e.target as HTMLInputElement).value;
            }}
            placeholder="session key"
          />
        </div>

        <div class="input-row">
          <input
            .value=${this.message}
            @input=${(e: Event) => {
              this.message = (e.target as HTMLInputElement).value;
            }}
            @keydown=${this.handleKeyDown}
            placeholder="Type a message"
          />
          <button
            type="button"
            @click=${() => void this.onSend()}
            ?disabled=${this.submitting || !g.connected}
          >
            ${this.submitting ? "Sending..." : "Send"}
          </button>
        </div>

        <div class="panel" style="margin-top: 12px">
          <h3>Last chat event</h3>
          <pre>${JSON.stringify(latest, null, 2) || "(none)"}</pre>
        </div>

        <div class="panel" style="margin-top: 12px">
          <h3>Local transcript</h3>
          <div class="chat-log">
            ${
              this.logLines.length === 0
                ? html`
                    <p class="muted">No messages yet.</p>
                  `
                : null
            }
            ${this.logLines.map((line) => html`<div>${line}</div>`)}
          </div>
        </div>
      </section>
    `;
  }
}
