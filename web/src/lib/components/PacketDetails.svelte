<script lang="ts">
  import { learningTextFor } from '../learning';
  import type { ByteRange, Packet } from '../model';
  let {
    packet,
    learningMode = false,
    selectedByteRange = null,
    onSelectByteRange = () => undefined,
  }: {
    packet: Packet;
    learningMode?: boolean;
    selectedByteRange?: ByteRange | null;
    onSelectByteRange?: (range: ByteRange) => void;
  } = $props();
  const tcpLayer = $derived(packet.layers.find((layer) => layer.protocol === 'TCP'));
  const tcpFlags = $derived(tcpLayer?.fields.find((field) => field.name.toLowerCase() === 'flags'));
  const protocol = $derived(
    packet.layers.find((layer) => !['ETHERNET', 'IPV4', 'IPV6'].includes(layer.protocol))
      ?.protocol ??
      packet.layers.at(-1)?.protocol ??
      'UNKNOWN',
  );
  const tcpFallbackKey = (value: string | undefined) => {
    const flags = value?.toUpperCase();
    if (flags === 'SYN') return 'tcp.syn';
    if (flags === 'SYN + ACK') return 'tcp.syn-ack';
    if (flags?.includes('RST')) return 'tcp.rst';
    if (flags?.includes('FIN')) return 'tcp.fin';
    if (flags === 'ACK') return 'tcp.ack';
    return null;
  };
  const explanationKey = (protocol: string, layerKey: string | null) =>
    protocol === 'TCP'
      ? (tcpFlags?.explanationKey ?? tcpFallbackKey(tcpFlags?.value) ?? layerKey)
      : layerKey;
  const rangeIsSelected = (range: ByteRange | null) =>
    range !== null &&
    selectedByteRange !== null &&
    range.captureOffset === selectedByteRange.captureOffset &&
    range.packetOffset === selectedByteRange.packetOffset &&
    range.length === selectedByteRange.length;
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
        <div class="layer-heading">
          <h3>{layer.protocol}</h3>
          {#if layer.byteRange}<button
              class="byte-control"
              type="button"
              aria-label={`Show ${layer.protocol} layer bytes`}
              aria-pressed={rangeIsSelected(layer.byteRange)}
              onclick={() => onSelectByteRange(layer.byteRange!)}>Show bytes</button
            >{/if}
        </div>
        <p>{layer.label}</p>
        <dl>
          {#each layer.fields as field (field.name)}<div>
              <dt>{field.name}</dt>
              <dd>
                <span>{field.value}</span>{#if field.byteRange}<button
                    class="byte-control field-byte-control"
                    type="button"
                    aria-label={`Show ${field.name} field bytes`}
                    aria-pressed={rangeIsSelected(field.byteRange)}
                    onclick={() => onSelectByteRange(field.byteRange!)}>Show bytes</button
                  >{/if}
              </dd>
            </div>{/each}
        </dl>
        {#if learningMode}<p class="learning">
            <strong>What this means:</strong>
            {learningTextFor(layer.protocol, explanationKey(layer.protocol, layer.explanationKey))}
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
  .layer-heading {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
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
    display: flex;
    align-items: start;
    justify-content: space-between;
    gap: 0.5rem;
    min-width: 0;
    margin: 0;
    color: var(--ink);
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .byte-control {
    flex: 0 0 auto;
    padding: 0.28rem 0.45rem;
    border: 1px solid var(--line-strong);
    border-radius: 0.35rem;
    background: var(--surface);
    color: var(--accent);
    font: inherit;
    font-size: 0.68rem;
    font-weight: 750;
    cursor: pointer;
  }
  .byte-control:hover,
  .byte-control[aria-pressed='true'] {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .byte-control:focus-visible {
    outline: 3px solid var(--accent-soft);
    outline-offset: 2px;
  }
  .field-byte-control {
    margin-top: -0.15rem;
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
