<script lang="ts">
  import type { CaptureDocument, Packet } from '../model';
  import { elapsedMilliseconds } from '../time';
  let {
    document,
    selectedPacketId = '',
    onSelect,
  }: {
    document: CaptureDocument;
    selectedPacketId?: string;
    onSelect: (id: string) => void;
  } = $props();
  const endpoint = (id: string | null) => document.endpoints.find((item) => item.id === id);
  const protocol = (packet: Packet) =>
    packet.layers.find((item) => !['ETHERNET', 'IPV4', 'IPV6'].includes(item.protocol))?.protocol ??
    packet.layers.at(-1)?.protocol ??
    'UNKNOWN';
</script>

<section id="packets" class="packet-table" aria-labelledby="packets-title">
  <div class="section-heading">
    <div>
      <p class="eyebrow">Evidence, explained</p>
      <h2 id="packets-title">Packets</h2>
    </div>
    <span class="count">{document.packets.length}</span>
  </div>
  <div class="table-wrap">
    <table>
      <caption>Packet list. Select a row to inspect its protocol layers.</caption><thead
        ><tr
          ><th scope="col">Packet</th><th scope="col">Time</th><th scope="col"
            >Source → destination</th
          ><th scope="col">Protocol</th><th scope="col">Length</th></tr
        ></thead
      >
      <tbody
        >{#each document.packets as packet (packet.id)}<tr
            ><td
              ><button
                class:selected={selectedPacketId === packet.id}
                aria-current={selectedPacketId === packet.id ? 'true' : undefined}
                aria-label={`Packet ${packet.number}: ${packet.summary}`}
                onclick={() => onSelect(packet.id)}>{packet.number}</button
              ></td
            ><td
              >{elapsedMilliseconds(
                document.packets[0]?.timestampNs ?? packet.timestampNs,
                packet.timestampNs,
              )}</td
            ><td
              >{endpoint(packet.sourceEndpointId)?.address ?? 'Unknown'} → {endpoint(
                packet.destinationEndpointId,
              )?.address ?? 'Unknown'}</td
            ><td
              ><span class="protocol">{protocol(packet)}</span><br /><small>{packet.summary}</small
              ></td
            ><td>{packet.capturedLength} B</td></tr
          >{/each}</tbody
      >
    </table>
  </div>
</section>

<style>
  .packet-table {
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
  .count {
    min-width: 1.6rem;
    padding: 0.2rem 0.45rem;
    border-radius: 999px;
    background: var(--surface-alt);
    color: var(--muted);
    font-size: 0.78rem;
    text-align: center;
  }
  .table-wrap {
    overflow-x: auto;
  }
  table {
    width: 100%;
    min-width: 620px;
    border-collapse: collapse;
    font-size: 0.8rem;
  }
  caption {
    margin-bottom: 0.55rem;
    color: var(--muted);
    font-size: 0.75rem;
    text-align: left;
  }
  th,
  td {
    padding: 0.7rem 0.55rem;
    border-top: 1px solid var(--line);
    text-align: left;
    vertical-align: top;
  }
  th {
    color: var(--muted);
    font-size: 0.72rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  td {
    color: var(--muted);
  }
  td:first-child {
    width: 4.5rem;
  }
  td small {
    line-height: 1.4;
  }
  button {
    min-width: 2.3rem;
    padding: 0.35rem 0.5rem;
    border: 1px solid var(--line-strong);
    border-radius: 0.4rem;
    background: var(--surface-alt);
    color: var(--ink);
    font-weight: 700;
    cursor: pointer;
  }
  button:hover,
  button.selected {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .protocol {
    color: var(--accent);
    font-weight: 700;
  }
</style>
