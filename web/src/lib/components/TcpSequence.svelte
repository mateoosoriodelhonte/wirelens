<script lang="ts">
  import { tcpEventLearningText } from '../learning';
  import type { CaptureDocument, TcpFlow, TcpFlowEvent } from '../model';
  import { elapsedMilliseconds } from '../time';
  let { document, flow }: { document: CaptureDocument; flow: TcpFlow } = $props();
  const packet = (number: number) => document.packets.find((item) => item.number === number);
  const endpoint = (id: string) => document.endpoints.find((item) => item.id === id);
  const direction = (event: TcpFlowEvent) =>
    packet(event.packetNumber)?.sourceEndpointId === flow.clientEndpointId
      ? 'client-to-server'
      : 'server-to-client';
  const elapsed = (event: TcpFlowEvent) =>
    elapsedMilliseconds(flow.startTimestampNs, packet(event.packetNumber)?.timestampNs ?? null);
  const eventPosition = (index: number) => 20 + index * (60 / Math.max(flow.events.length - 1, 1));
  const termination = (value: TcpFlow['termination']) =>
    ({
      graceful: 'Graceful close',
      reset: 'Reset observed',
      'open-at-capture-end': 'Open at capture end',
      unknown: 'Close state unknown',
    })[value];
</script>

<section class="sequence" aria-labelledby="sequence-title">
  <div class="section-heading">
    <div>
      <p class="eyebrow">TCP flow</p>
      <h2 id="sequence-title">Connection sequence</h2>
    </div>
    <div class="states" aria-label="TCP connection state">
      <span class="state">{flow.handshake} handshake</span>
      <span class="state termination">{termination(flow.termination)}</span>
    </div>
  </div>
  {#if flow.midStream}
    <p class="flow-note">
      The initial SYN was not observed. Direction uses the first packet in this capture.
    </p>
  {/if}
  <div
    class="diagram"
    aria-hidden="true"
    style={`--sequence-height: ${Math.max(7, flow.events.length * 1.5)}rem`}
  >
    <div class="lane">
      <span>Client<br /><small>{endpoint(flow.clientEndpointId)?.address}</small></span><span
        class="line"
      ></span>
    </div>
    <div class="lane">
      <span>Server<br /><small>{endpoint(flow.serverEndpointId)?.address}</small></span><span
        class="line"
      ></span>
    </div>
    {#each flow.events as event, index (event.packetNumber)}<div
        class="event event-{direction(event)}"
        data-label={event.label}
        style={`--event-position: ${eventPosition(index)}%`}
      >
        <span class="event-mark">{direction(event) === 'client-to-server' ? '↗' : '↙'}</span>
      </div>{/each}
  </div>
  <table aria-label="Text alternative for TCP sequence">
    <caption>TCP sequence events</caption><thead
      ><tr
        ><th scope="col">Packet</th><th scope="col">Event</th><th scope="col">Direction</th><th
          scope="col">Time from start</th
        ></tr
      ></thead
    ><tbody
      >{#each flow.events as event (event.packetNumber)}<tr
          ><th scope="row">{event.packetNumber}</th><td
            ><strong>{event.label}</strong><br /><span>{tcpEventLearningText(event.label)}</span></td
          ><td>{direction(event) === 'client-to-server' ? 'Client → server' : 'Server → client'}</td
          ><td>{elapsed(event)}</td></tr
        >{/each}</tbody
    >
  </table>
</section>

<style>
  .sequence {
    display: grid;
    gap: 1.3rem;
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
  .states {
    display: flex;
    flex-wrap: wrap;
    justify-content: end;
    gap: 0.4rem;
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
  .state {
    padding: 0.35rem 0.6rem;
    border: 1px solid var(--success);
    border-radius: 999px;
    color: var(--success);
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: capitalize;
  }
  .state.termination {
    border-color: var(--line-strong);
    color: var(--muted);
  }
  .flow-note {
    margin: -0.45rem 0 0;
    padding: 0.65rem 0.75rem;
    border-left: 3px solid var(--accent);
    background: var(--accent-soft);
    color: var(--muted);
    font-size: 0.78rem;
    line-height: 1.45;
  }
  .diagram {
    position: relative;
    display: grid;
    gap: 1.4rem;
    min-height: var(--sequence-height);
    padding: 0.7rem 0;
    overflow: hidden;
  }
  .lane {
    display: flex;
    align-items: center;
    gap: 1rem;
    color: var(--ink);
    font-size: 0.8rem;
    font-weight: 700;
  }
  .lane small {
    color: var(--muted);
    font-weight: 500;
  }
  .line {
    height: 1px;
    flex: 1;
    background: var(--line-strong);
  }
  .event {
    position: absolute;
    top: calc(var(--event-position) * 0.95);
    display: flex;
    align-items: center;
    gap: 0.3rem;
    color: var(--ink);
    font-size: 0.73rem;
    font-weight: 700;
  }
  .event-client-to-server {
    left: 30%;
  }
  .event-server-to-client {
    right: 8%;
  }
  .event-mark {
    color: var(--accent);
    font-size: 1.05rem;
  }
  .event::after {
    content: attr(data-label);
    color: var(--ink);
    font-size: 0.73rem;
    font-weight: 700;
  }
  table {
    width: 100%;
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
    padding: 0.65rem 0.5rem;
    border-top: 1px solid var(--line);
    text-align: left;
    vertical-align: top;
  }
  th {
    color: var(--ink);
    font-weight: 700;
  }
  td {
    color: var(--muted);
  }
  td strong {
    color: var(--ink);
  }
  td span {
    line-height: 1.45;
  }
  @media (max-width: 620px) {
    .diagram {
      display: none;
    }
    table {
      font-size: 0.74rem;
    }
    th,
    td {
      padding-inline: 0.25rem;
    }
  }
</style>
