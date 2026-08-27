<script lang="ts">
  import type { Packet } from '../model';
  let { packet, learningMode = false }: { packet: Packet; learningMode?: boolean } = $props();
  const tcpLayer = $derived(packet.layers.find((layer) => layer.protocol === 'TCP'));
  const tcpFlags = $derived(tcpLayer?.fields.find((field) => field.name.toLowerCase() === 'flags'));
  const protocol = $derived(
    packet.layers.find((layer) => !['ETHERNET', 'IPV4', 'IPV6'].includes(layer.protocol))
      ?.protocol ??
      packet.layers.at(-1)?.protocol ??
      'UNKNOWN',
  );
  const explanation = (key: string | null, value: string | undefined) => {
    const fallback = value?.toUpperCase();
    return key === 'tcp.syn' || (key === null && fallback === 'SYN')
      ? 'Synchronize sequence numbers to begin a connection.'
      : key === 'tcp.syn-ack' || (key === null && fallback === 'SYN + ACK')
        ? 'The server accepts and acknowledges the client request.'
        : key === 'tcp.ack' || (key === null && fallback === 'ACK')
          ? 'The client acknowledges the server and completes the handshake.'
          : 'This field describes evidence in the selected protocol layer.';
  };
</script>

<section class="details" aria-labelledby="details-title">
  <div class="section-heading">
    <div>
      <p class="eyebrow">Packet {packet.number}</p>
      <h2 id="details-title" tabindex="-1">Packet details</h2>
    </div>
    <span class="protocol-tag">{protocol}</span>
  </div>
  <p class="summary">{packet.summary}</p>
  <div class="layers">
    {#each packet.layers as layer (layer.protocol)}<article class="layer">
        <h3>{layer.protocol}</h3>
        <p>{layer.label}</p>
        <dl>
          {#each layer.fields as field (field.name)}<div>
              <dt>{field.name}</dt>
              <dd>{field.value}</dd>
            </div>{/each}
        </dl>
        {#if learningMode && layer.protocol === 'TCP'}<p class="learning">
            <strong>What this means:</strong>
            {explanation(tcpFlags?.explanationKey ?? layer.explanationKey, tcpFlags?.value)}
          </p>{/if}
      </article>{/each}
  </div>
</section>

<style>
  .details {
    display: grid;
    gap: 1rem;
    padding: 1.5rem;
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 1rem;
  }
  .section-heading {
    display: flex;
    justify-content: space-between;
    align-items: start;
  }
  .eyebrow {
    margin: 0 0 0.35rem;
    color: var(--accent);
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }
  h2 {
    margin: 0;
    font-size: 1.35rem;
    letter-spacing: -0.03em;
  }
  .protocol-tag {
    padding: 0.35rem 0.55rem;
    border-radius: 0.35rem;
    background: var(--accent-soft);
    color: var(--accent);
    font-size: 0.72rem;
    font-weight: 800;
  }
  .summary {
    margin: 0;
    color: var(--ink);
    font-weight: 600;
  }
  .layers {
    display: grid;
    gap: 0.65rem;
  }
  .layer {
    min-width: 0;
    padding: 1rem;
    border: 1px solid var(--line);
    border-radius: 0.65rem;
    background: var(--surface-alt);
  }
  h3 {
    margin: 0;
    color: var(--ink);
    font-size: 0.9rem;
    letter-spacing: 0.03em;
  }
  .layer > p {
    margin: 0.3rem 0 0.75rem;
    color: var(--muted);
    font-size: 0.8rem;
  }
  dl {
    display: grid;
    gap: 0.4rem;
    margin: 0;
  }
  dl div {
    display: grid;
    grid-template-columns: minmax(9rem, 0.8fr) minmax(0, 1fr);
    gap: 0.6rem;
    font-size: 0.78rem;
  }
  dt {
    color: var(--muted);
    overflow-wrap: anywhere;
  }
  dd {
    min-width: 0;
    margin: 0;
    color: var(--ink);
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .learning {
    padding: 0.75rem;
    border-left: 3px solid var(--accent);
    background: var(--surface);
    color: var(--ink) !important;
  }
  .learning strong {
    color: var(--accent);
  }
</style>
