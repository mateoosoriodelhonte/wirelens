<script lang="ts">
  import type { TlsHandshake, TlsClientHello, TlsServerHello } from '../model';

  let {
    handshakes,
    onSelectPacket,
  }: {
    handshakes: TlsHandshake[];
    onSelectPacket: (packetNumber: number) => void;
  } = $props();

  const visibleServerName = (serverName: string | null) => serverName ?? 'Not visible';
  const versionList = (versions: string[]) =>
    versions.length > 0 ? versions.join(', ') : 'None observed';
</script>

<section id="tls" class="tls" aria-labelledby="tls-title">
  <div class="section-heading">
    <div>
      <p class="eyebrow">Handshake metadata only</p>
      <h2 id="tls-title">TLS handshakes</h2>
    </div>
    <span class="count">{handshakes.length}</span>
  </div>

  {#if handshakes.length === 0}
    <p class="empty">No TLS handshakes were found in this capture.</p>
  {:else}
    <div class="handshake-list">
      {#each handshakes as handshake (handshake.id)}
        <article class:unmatched={!handshake.matched} class="handshake">
          <div class="handshake-heading">
            <div>
              <p class="handshake-label">TLS handshake</p>
              <h3>Flow {handshake.flowId}</h3>
            </div>
            <span class:matched={handshake.matched} class="status">
              {handshake.matched ? 'Matched' : 'Unmatched'}
            </span>
          </div>

          <div class="hello-grid">
            {#if handshake.clientHello}
              {@render HelloCard(handshake.clientHello, 'ClientHello', onSelectPacket)}
            {/if}
            {#if handshake.serverHello}
              {@render HelloCard(handshake.serverHello, 'ServerHello', onSelectPacket)}
            {/if}
          </div>

          {#if !handshake.matched}
            <p class="state-note">The ClientHello and ServerHello could not be paired safely.</p>
          {/if}
          <p class="limitation">
            {handshake.limitation || 'WireLens does not decrypt TLS application data.'}
          </p>
        </article>
      {/each}
    </div>
  {/if}
</section>

{#snippet HelloCard(
  hello: TlsClientHello | TlsServerHello,
  kind: 'ClientHello' | 'ServerHello',
  onSelectPacket: (packetNumber: number) => void,
)}
  <article class="hello" aria-label={kind}>
    <h3>{kind}</h3>
    <dl>
      <div>
        <dt>Record version</dt>
        <dd>{hello.recordVersion}</dd>
      </div>
      <div>
        <dt>Legacy version</dt>
        <dd>{hello.legacyVersion}</dd>
      </div>
      {#if kind === 'ClientHello'}
        <div>
          <dt>Offered versions</dt>
          <dd>{versionList((hello as TlsClientHello).offeredVersions)}</dd>
        </div>
        <div>
          <dt>SNI</dt>
          <dd>{visibleServerName((hello as TlsClientHello).serverName)}</dd>
        </div>
      {:else}
        <div>
          <dt>Negotiated version</dt>
          <dd>{(hello as TlsServerHello).negotiatedVersion ?? 'Not negotiated'}</dd>
        </div>
      {/if}
    </dl>
    <div class="evidence" aria-label={`${kind} packet evidence`}>
      {#each hello.packetNumbers as packetNumber (`${kind}-${packetNumber}`)}
        <button
          type="button"
          aria-label={`View TLS ${kind} packet ${packetNumber}`}
          onclick={() => onSelectPacket(packetNumber)}>Packet {packetNumber} · {kind}</button
        >
      {/each}
    </div>
  </article>
{/snippet}

<style>
  .tls {
    display: grid;
    gap: 1rem;
    padding: 1.5rem;
    border: 1px solid var(--line);
    border-radius: 1rem;
    background: var(--surface);
  }
  .section-heading,
  .handshake-heading {
    display: flex;
    justify-content: space-between;
    align-items: start;
    gap: 1rem;
  }
  .eyebrow,
  .handshake-label {
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
  .handshake-list {
    display: grid;
    gap: 0.75rem;
  }
  .handshake {
    display: grid;
    gap: 0.85rem;
    padding: 1rem;
    border: 1px solid var(--line);
    border-radius: 0.7rem;
    background: var(--surface-alt);
  }
  .handshake.unmatched {
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
  .hello-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 18rem), 1fr));
    gap: 0.65rem;
  }
  .hello {
    display: grid;
    gap: 0.7rem;
    min-width: 0;
    padding: 0.85rem;
    border: 1px solid var(--line);
    border-radius: 0.5rem;
    background: var(--surface);
  }
  dl {
    display: grid;
    gap: 0.4rem;
    margin: 0;
  }
  dl div {
    display: grid;
    grid-template-columns: minmax(7rem, 0.75fr) minmax(0, 1fr);
    gap: 0.6rem;
  }
  dt {
    color: var(--muted);
    font-size: 0.68rem;
    text-transform: uppercase;
  }
  dd {
    min-width: 0;
    margin: 0;
    color: var(--ink);
    font-size: 0.78rem;
    font-weight: 650;
    overflow-wrap: anywhere;
  }
  .state-note,
  .empty {
    color: var(--muted);
    font-size: 0.8rem;
    line-height: 1.5;
  }
  .limitation {
    padding: 0.75rem;
    border-left: 3px solid var(--accent);
    background: var(--surface);
    color: var(--ink);
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
