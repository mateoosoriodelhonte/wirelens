<script lang="ts">
  import type { CaptureDocument } from '../model';
  import { formatMilliseconds } from '../time';
  let { document }: { document: CaptureDocument } = $props();
  const durationMs = $derived(formatMilliseconds(document.capture.durationNs));
  const bytes = $derived(document.capture.capturedBytes.toLocaleString());
</script>

<section id="overview" class="overview" aria-labelledby="overview-title">
  <div class="section-heading">
    <div>
      <p class="eyebrow">Evidence summary</p>
      <h2 id="overview-title" tabindex="-1">Capture overview</h2>
    </div>
    <span class="privacy">Local only</span>
  </div>
  <div class="metrics" role="list" aria-label="Capture metrics">
    <div class="metric" role="listitem">
      <span>Packets</span><strong>{document.capture.packetCount} packets</strong><small
        >{bytes} captured bytes</small
      >
    </div>
    <div class="metric" role="listitem">
      <span>Duration</span><strong>{durationMs}</strong><small>from first to last packet</small>
    </div>
    <div class="metric" role="listitem">
      <span>Conversations</span><strong>{document.flows.length}</strong><small
        >{document.flows.every((flow) => flow.protocol === 'TCP') ? 'TCP ' : ''}flow{document.flows.length === 1 ? '' : 's'}</small
      >
    </div>
  </div>
  <div class="facts">
    <div><span>Format</span><b>{document.capture.format.toUpperCase()}</b></div>
    <div><span>Endpoints</span><b>{document.endpoints.length}</b></div>
    <div>
      <span>Diagnostics</span><b
        >{document.diagnostics.length ? document.diagnostics.length : 'None'}</b
      >
    </div>
  </div>
</section>

<style>
  .overview {
    display: grid;
    gap: 1.2rem;
    padding: 1.5rem;
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 1rem;
  }
  .section-heading {
    display: flex;
    align-items: start;
    justify-content: space-between;
    gap: 1rem;
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
  .privacy {
    padding: 0.35rem 0.6rem;
    border: 1px solid var(--line);
    border-radius: 999px;
    color: var(--success);
    font-size: 0.75rem;
    font-weight: 700;
    white-space: nowrap;
  }
  .metrics {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.75rem;
  }
  .metric {
    display: grid;
    gap: 0.35rem;
    padding: 1rem;
    border-radius: 0.7rem;
    background: var(--surface-alt);
  }
  .metric span,
  .facts span {
    color: var(--muted);
    font-size: 0.77rem;
    font-weight: 600;
  }
  .metric strong {
    color: var(--ink);
    font-size: 1.35rem;
    letter-spacing: -0.03em;
  }
  .metric small {
    color: var(--muted);
    font-size: 0.75rem;
  }
  .facts {
    display: flex;
    flex-wrap: wrap;
    gap: 1.5rem;
    padding-top: 0.2rem;
  }
  .facts div {
    display: grid;
    gap: 0.2rem;
  }
  .facts b {
    color: var(--ink);
    font-size: 0.85rem;
  }
  @media (max-width: 620px) {
    .metrics {
      grid-template-columns: 1fr;
    }
  }
</style>
