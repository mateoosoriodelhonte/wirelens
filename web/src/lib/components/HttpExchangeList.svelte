<script lang="ts">
  import type { HttpExchange, HttpHeader } from '../model';
  import { formatMilliseconds } from '../time';

  let {
    exchanges,
    onSelectPacket,
  }: {
    exchanges: HttpExchange[];
    onSelectPacket: (packetNumber: number) => void;
  } = $props();

  const latency = (nanoseconds: string | null) =>
    nanoseconds === null ? null : formatMilliseconds(nanoseconds);

  const headerValue = (header: HttpHeader) =>
    header.redacted || header.value === null ? '[redacted]' : header.value;
</script>

<section id="http" class="http" aria-labelledby="http-title">
  <div class="section-heading">
    <div>
      <p class="eyebrow">Sanitized plaintext metadata</p>
      <h2 id="http-title">HTTP exchanges</h2>
    </div>
    <span class="count">{exchanges.length}</span>
  </div>

  {#if exchanges.length === 0}
    <p class="empty">No HTTP exchanges were found in this capture.</p>
  {:else}
    <div class="exchange-list">
      {#each exchanges as exchange (exchange.id)}
        <article class:unmatched={!exchange.matched} class="exchange">
          <div class="exchange-heading">
            <div>
              <p class="exchange-label">HTTP exchange</p>
              <h3>{exchange.request?.target ?? exchange.response?.line ?? 'Unpaired message'}</h3>
            </div>
            <span class:matched={exchange.matched} class="status">
              {exchange.matched ? 'Matched' : 'Unmatched'}
            </span>
          </div>

          {#if exchange.request}
            <div class="message" aria-label="HTTP request">
              <span class="message-label">Request</span>
              <code>{exchange.request.line}</code>
              {#if exchange.request.headers.length > 0}
                <dl class="headers">
                  {#each exchange.request.headers as header, headerIndex (`request-${exchange.id}-${header.name}-${headerIndex}`)}
                    <div>
                      <dt>{header.name}</dt>
                      <dd class:redacted={header.redacted || header.value === null}>
                        {headerValue(header)}
                      </dd>
                    </div>
                  {/each}
                </dl>
              {/if}
            </div>
          {/if}

          {#if exchange.response}
            <div class="message" aria-label="HTTP response">
              <span class="message-label">Response</span>
              <code>{exchange.response.line}</code>
              {#if exchange.response.headers.length > 0}
                <dl class="headers">
                  {#each exchange.response.headers as header, headerIndex (`response-${exchange.id}-${header.name}-${headerIndex}`)}
                    <div>
                      <dt>{header.name}</dt>
                      <dd class:redacted={header.redacted || header.value === null}>
                        {headerValue(header)}
                      </dd>
                    </div>
                  {/each}
                </dl>
              {/if}
            </div>
          {/if}

          <dl class="facts">
            <div>
              <dt>Latency</dt>
              <dd>{latency(exchange.latencyNs) ?? 'Not available'}</dd>
            </div>
          </dl>

          {#if !exchange.matched}
            <p class="state-note">
              {#if exchange.request && !exchange.response}
                No matching response was found for this request.
              {:else if exchange.response && !exchange.request}
                No matching request was found for this response.
              {:else}
                This HTTP message could not be paired safely.
              {/if}
            </p>
          {/if}

          <div class="evidence" aria-label="HTTP packet evidence">
            {#if exchange.request}
              {#each exchange.request.packetNumbers as packetNumber (`request-packet-${exchange.id}-${packetNumber}`)}
                <button
                  type="button"
                  aria-label={`View HTTP request packet ${packetNumber}`}
                  onclick={() => onSelectPacket(packetNumber)}
                  >Packet {packetNumber} · request</button
                >
              {/each}
            {/if}
            {#if exchange.response}
              {#each exchange.response.packetNumbers as packetNumber (`response-packet-${exchange.id}-${packetNumber}`)}
                <button
                  type="button"
                  aria-label={`View HTTP response packet ${packetNumber}`}
                  onclick={() => onSelectPacket(packetNumber)}
                  >Packet {packetNumber} · response</button
                >
              {/each}
            {/if}
          </div>
        </article>
      {/each}
    </div>
  {/if}
</section>

<style>
  .http {
    display: grid;
    gap: 1rem;
    padding: 1.5rem;
    border: 1px solid var(--line);
    border-radius: 1rem;
    background: var(--surface);
  }
  .section-heading,
  .exchange-heading {
    display: flex;
    justify-content: space-between;
    align-items: start;
    gap: 1rem;
  }
  .eyebrow,
  .exchange-label {
    margin: 0 0 0.35rem;
    color: var(--accent);
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }
  h2,
  h3,
  p {
    margin: 0;
  }
  h2 {
    font-size: 1.35rem;
    letter-spacing: -0.03em;
  }
  h3 {
    overflow-wrap: anywhere;
    font-size: 1rem;
    letter-spacing: -0.02em;
  }
  .count {
    min-width: 1.6rem;
    padding: 0.2rem 0.45rem;
    border-radius: 999px;
    background: var(--surface-alt);
    color: var(--muted);
    font-size: 0.78rem;
    text-align: center;
  }
  .exchange-list {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 24rem), 1fr));
    gap: 0.75rem;
  }
  .exchange {
    display: grid;
    align-content: start;
    gap: 0.85rem;
    min-width: 0;
    padding: 1rem;
    border: 1px solid var(--line);
    border-radius: 0.7rem;
    background: var(--surface-alt);
  }
  .exchange.unmatched {
    border-style: dashed;
  }
  .status {
    padding: 0.25rem 0.45rem;
    border-radius: 999px;
    background: var(--surface);
    color: var(--muted);
    font-size: 0.7rem;
    font-weight: 800;
  }
  .status.matched {
    background: var(--accent-soft);
    color: var(--success);
  }
  .message {
    display: grid;
    gap: 0.45rem;
    min-width: 0;
    padding: 0.75rem;
    border: 1px solid var(--line);
    border-radius: 0.5rem;
    background: var(--surface);
  }
  .message-label,
  dt {
    color: var(--muted);
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  code {
    overflow-wrap: anywhere;
    color: var(--ink);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.8rem;
    line-height: 1.5;
    white-space: pre-wrap;
  }
  .headers,
  .facts {
    display: grid;
    gap: 0.4rem;
    margin: 0;
  }
  .headers div,
  .facts div {
    display: grid;
    grid-template-columns: minmax(7rem, 0.5fr) minmax(0, 1fr);
    gap: 0.6rem;
  }
  dd {
    min-width: 0;
    margin: 0;
    color: var(--ink);
    font-size: 0.78rem;
    font-weight: 650;
    overflow-wrap: anywhere;
  }
  dd.redacted {
    color: var(--muted);
    font-style: italic;
  }
  .state-note,
  .empty {
    color: var(--muted);
    font-size: 0.8rem;
    line-height: 1.5;
  }
  .evidence {
    display: flex;
    flex-wrap: wrap;
    gap: 0.45rem;
  }
  button {
    padding: 0.4rem 0.55rem;
    border: 1px solid var(--line-strong);
    border-radius: 0.4rem;
    background: var(--surface);
    color: var(--accent);
    font-size: 0.72rem;
    font-weight: 750;
    cursor: pointer;
  }
  button:hover {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
</style>
