import { consume } from "@lit/context";
import { LitElement, html } from "lit";
import { customElement, state } from "lit/decorators.js";
import { gatewayContext } from "../context/gateway-context.js";

@customElement("overview-view")
export class OverviewView extends LitElement {
  @consume({ context: gatewayContext, subscribe: true })
  gateway!: import("../context/gateway-context.js").GatewayState;

  @state() gatewayUrlInput = "";
  @state() sharedSecretInput = "";

  override createRenderRoot() {
    return this;
  }

  override updated(): void {
    if (this.gateway && !this.gatewayUrlInput) {
      this.gatewayUrlInput = this.gateway.gatewayUrl;
    }
  }

  private onReconnect = (): void => {
    if (!this.gateway) {
      return;
    }
    this.gateway.reconnect({
      gatewayUrl: this.gatewayUrlInput,
      sharedSecret: this.sharedSecretInput,
    });
  };

  private handleReconnectKeyDown = (e: KeyboardEvent): void => {
    if (e.key === "Enter") {
      this.onReconnect();
    }
  };

  override render() {
    const g = this.gateway;
    if (!g) {
      return html`
        <p class="muted">Loading...</p>
      `;
    }

    const error = g.lastError || "";
    const lowerError = error.toLowerCase();
    const isPasswordMismatch =
      lowerError.includes("password mismatch") || lowerError.includes("token mismatch");

    return html`
      <section class="panel">
        <h2>Connection</h2>
        <div class="status-row">
          <span class="status-pill">${g.connected ? "Connected" : "Disconnected"}</span>
          <span class="status-pill">${g.connecting ? "Reconnecting" : "Stable"}</span>
        </div>
        ${g.lastError ? html`<p class="error">${g.lastError}</p>` : null}

        ${
          isPasswordMismatch
            ? html`
                <div class="panel" style="margin-top: 10px">
                  <strong>Password mismatch fix</strong>
                  <ol>
                    <li>Get the gateway password/shared secret:</li>
                  </ol>
                  <pre>openclaw config get gateway.auth.password</pre>
                  <p class="muted">If empty, try:</p>
                  <pre>openclaw config get gateway.auth.token</pre>
                  <ol start="2">
                    <li>Paste that value below and click <b>Save & reconnect</b>.</li>
                    <li>If you do not run the gateway yourself, ask the gateway admin for the secret.</li>
                  </ol>
                </div>
              `
            : null
        }

        <div class="input-row">
          <input
            .value=${this.gatewayUrlInput}
            @input=${(e: Event) => {
              this.gatewayUrlInput = (e.target as HTMLInputElement).value;
            }}
            @keydown=${this.handleReconnectKeyDown}
            placeholder="ws://127.0.0.1:18789"
          />
        </div>
        <div class="input-row">
          <input
            type="password"
            .value=${this.sharedSecretInput}
            @input=${(e: Event) => {
              this.sharedSecretInput = (e.target as HTMLInputElement).value;
            }}
            @keydown=${this.handleReconnectKeyDown}
            placeholder="Gateway shared secret (password/token)"
          />
          <button type="button" @click=${this.onReconnect}>Save & reconnect</button>
        </div>

        <p class="muted">Tip: use ?token=...&gatewayUrl=... once to bootstrap local settings.</p>
      </section>

      <section class="panel">
        <h2>Hello snapshot</h2>
        <pre>${JSON.stringify(g.hello, null, 2) || "(waiting for hello-ok)"}</pre>
      </section>

      <section class="panel">
        <h2>Latest event</h2>
        <pre>${JSON.stringify(g.lastEvent, null, 2) || "(no events yet)"}</pre>
      </section>
    `;
  }
}
