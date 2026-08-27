<script lang="ts">
  import type { DnsExchange, Observation } from '../model';

  let {
    exchanges,
    observations,
    onSelectPacket,
  }: {
    exchanges: DnsExchange[];
    observations: Observation[];
    onSelectPacket: (packetNumber: number) => void;
  } = $props();

  const recordType = (type: number) => (type === 1 ? 'A' : type === 28 ? 'AAAA' : `TYPE ${type}`);
  const latency = (nanoseconds: string | null) => {
    if (nanoseconds === null) return null;
    const value = BigInt(nanoseconds);
    const whole = value / 1_000_000n;
    const remainder = value % 1_000_000n;
    if (remainder === 0n) return `${whole} ms`;
    const fraction = remainder.toString().padStart(6, '0').replace(/0+$/u, '');
    return `${whole}.${fraction} ms`;
  };
</script>

<section id="dns" class="dns" aria-labelledby="dns-title">
  <div class="section-heading">
    <div>
      <p class="eyebrow">Questions and answers</p>
      <h2 id="dns-title">DNS exchanges</h2>
    </div>
    <span class="count">{exchanges.length}</span>
  </div>

  {#if exchanges.length === 0}
    <p class="empty">No DNS exchanges were found in this capture.</p>
  {:else}
    <div class="exchange-list">
      {#each exchanges as exchange (exchange.id)}
        <article class:unmatched={!exchange.matched} class="exchange">
          <div class="exchange-heading">
            <div>
              <p class="question-type">{recordType(exchange.question.type)} question</p>
              <h3>{exchange.question.name}</h3>
            </div>
            <span class:matched={exchange.matched} class="status">
              {exchange.matched ? 'Matched' : 'Unmatched'}
            </span>
          </div>

          <dl class="facts">
            <div>
              <dt>Response</dt>
              <dd>{exchange.responseCode ?? 'Not observed'}</dd>
            </div>
            <div>
              <dt>Latency</dt>
              <dd>{latency(exchange.latencyNs) ?? 'Not available'}</dd>
            </div>
          </dl>

          {#if !exchange.matched}
            <p class="state-note">No response was matched to this question.</p>
          {:else if exchange.answers.length === 0}
            <p class="state-note">No selected A or AAAA answers were returned.</p>
          {:else}
            <ul class="answers" aria-label={`Answers for ${exchange.question.name}`}>
              {#each exchange.answers as answer, answerIndex (`${exchange.id}-answer-${answerIndex}`)}
                <li><span>{recordType(answer.type)}</span><strong>{answer.value}</strong></li>
              {/each}
            </ul>
          {/if}

          <div class="evidence" aria-label={`Packet evidence for ${exchange.question.name}`}>
            {#if exchange.queryPacketNumber !== null}
              <button
                type="button"
                aria-label={`View query packet ${exchange.queryPacketNumber} for ${exchange.question.name}`}
                onclick={() => onSelectPacket(exchange.queryPacketNumber!)}
                >Packet {exchange.queryPacketNumber} · query</button
              >
            {/if}
            {#if exchange.responsePacketNumber !== null}
              <button
                type="button"
                aria-label={`View response packet ${exchange.responsePacketNumber} for ${exchange.question.name}`}
                onclick={() => onSelectPacket(exchange.responsePacketNumber!)}
                >Packet {exchange.responsePacketNumber} · response</button
              >
            {/if}
          </div>
        </article>
      {/each}
    </div>
  {/if}

  {#if observations.length > 0}
    <div class="observations" aria-labelledby="dns-observations-title">
      <div class="observation-heading">
        <h3 id="dns-observations-title">DNS observations</h3>
        <span>{observations.length}</span>
      </div>
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
    </div>
  {/if}
</section>

<style>
  .dns {
    display: grid;
    gap: 1rem;
    padding: 1.5rem;
    border: 1px solid var(--line);
    border-radius: 1rem;
    background: var(--surface);
  }
  .section-heading,
  .exchange-heading,
  .observation-heading {
    display: flex;
    justify-content: space-between;
    align-items: start;
    gap: 1rem;
  }
  .eyebrow,
  .question-type {
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
  .count,
  .observation-heading span {
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
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 19rem), 1fr));
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
  .facts {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.5rem;
    margin: 0;
  }
  .facts div {
    min-width: 0;
    padding: 0.65rem;
    border: 1px solid var(--line);
    border-radius: 0.5rem;
    background: var(--surface);
  }
  dt {
    color: var(--muted);
    font-size: 0.68rem;
    text-transform: uppercase;
  }
  dd {
    margin: 0.2rem 0 0;
    color: var(--ink);
    font-size: 0.82rem;
    font-weight: 750;
    overflow-wrap: anywhere;
  }
  .answers,
  .observations ul {
    display: grid;
    gap: 0.45rem;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .answers li {
    display: grid;
    grid-template-columns: 3.5rem minmax(0, 1fr);
    gap: 0.6rem;
    color: var(--muted);
    font-size: 0.78rem;
  }
  .answers strong {
    color: var(--ink);
    overflow-wrap: anywhere;
  }
  .state-note,
  .empty,
  .observations p {
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
  .observations {
    display: grid;
    gap: 0.7rem;
    padding-top: 1rem;
    border-top: 1px solid var(--line);
  }
  .observations li {
    display: grid;
    gap: 0.4rem;
    padding: 0.85rem;
    border-left: 3px solid var(--accent);
    background: var(--surface-alt);
    font-size: 0.82rem;
  }
</style>
