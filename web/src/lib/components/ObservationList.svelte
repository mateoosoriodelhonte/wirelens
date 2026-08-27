<script lang="ts">
  import type { Observation } from '../model';

  let {
    observations,
    onSelectPacket,
  }: {
    observations: Observation[];
    onSelectPacket: (packetNumber: number) => void;
  } = $props();
</script>

<section id="observations" class="observations" aria-labelledby="observations-title">
  <div class="section-heading">
    <div>
      <p class="eyebrow">Evidence-based notes</p>
      <h2 id="observations-title">Observations</h2>
    </div>
    <span class="count">{observations.length}</span>
  </div>

  {#if observations.length === 0}
    <p class="empty">No additional observations were found in this capture.</p>
  {:else}
    <ul>
      {#each observations as observation (observation.id)}
        <li>
          <strong>{observation.message}</strong>
          <p>{observation.limitation}</p>
          <div class="evidence" aria-label={`Packet evidence for ${observation.message}`}>
            {#each observation.packetNumbers as packetNumber, evidenceIndex (`${observation.id}-packet-${evidenceIndex}`)}
              <button
                type="button"
                aria-label={`View evidence packet ${packetNumber} for ${observation.message}`}
                onclick={() => onSelectPacket(packetNumber)}>Packet {packetNumber}</button
              >
            {/each}
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .observations {
    display: grid;
    gap: 1rem;
    padding: 1.5rem;
    border: 1px solid var(--line);
    border-radius: 1rem;
    background: var(--surface);
  }
  .section-heading {
    display: flex;
    justify-content: space-between;
    align-items: start;
    gap: 1rem;
  }
  .eyebrow,
  h2,
  p {
    margin: 0;
  }
  .eyebrow {
    margin-bottom: 0.35rem;
    color: var(--accent);
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }
  h2 {
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
  ul {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 20rem), 1fr));
    gap: 0.75rem;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  li {
    display: grid;
    align-content: start;
    gap: 0.55rem;
    padding: 1rem;
    border-left: 3px solid var(--accent);
    border-radius: 0.25rem 0.7rem 0.7rem 0.25rem;
    background: var(--surface-alt);
    font-size: 0.84rem;
  }
  li strong {
    color: var(--ink);
    overflow-wrap: anywhere;
  }
  li p,
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
