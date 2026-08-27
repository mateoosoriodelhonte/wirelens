<script lang="ts">
  import type { Endpoint, TcpFlow } from '../model';
  let { flows, endpoints, selectedFlowId = '', onSelect }: { flows: TcpFlow[]; endpoints: Endpoint[]; selectedFlowId?: string; onSelect: (id: string) => void } = $props();
  const endpoint = (id: string) => endpoints.find((item) => item.id === id);
</script>

<section id="conversations" class="conversation" aria-labelledby="conversation-title">
  <div class="section-heading"><div><p class="eyebrow">Follow the evidence</p><h2 id="conversation-title">Conversations</h2></div><span class="count">{flows.length}</span></div>
  {#if flows.length}<ul>{#each flows as flow (flow.id)}<li><button class:selected={selectedFlowId === flow.id} aria-pressed={selectedFlowId === flow.id} onclick={() => onSelect(flow.id)}>
    <span class="flow-name"><span>{endpoint(flow.clientEndpointId)?.address}:{endpoint(flow.clientEndpointId)?.port}</span><span class="arrow" aria-hidden="true">→</span><span>{endpoint(flow.serverEndpointId)?.address}:{endpoint(flow.serverEndpointId)?.port}</span></span>
    <span class="flow-meta"><span>{flow.handshake === 'complete' ? 'Handshake complete' : 'Handshake incomplete'}</span><span>{flow.packetNumbers.length} packets · {flow.capturedBytes} bytes</span></span>
  </button></li>{/each}</ul>{:else}<p class="empty">No conversations were found in this capture.</p>{/if}
</section>

<style>
  .conversation { display: grid; gap: 1rem; padding: 1.5rem; background: var(--surface); border: 1px solid var(--line); border-radius: 1rem; }
  .section-heading { display: flex; justify-content: space-between; align-items: start; } .eyebrow { margin: 0 0 .35rem; color: var(--accent); font-size: .72rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; } h2 { margin: 0; font-size: 1.35rem; letter-spacing: -.03em; } .count { min-width: 1.6rem; padding: .2rem .45rem; border-radius: 999px; background: var(--surface-alt); color: var(--muted); font-size: .78rem; text-align: center; }
  ul { display: grid; gap: .55rem; padding: 0; margin: 0; list-style: none; } button { display: grid; width: 100%; gap: .55rem; padding: .9rem 1rem; border: 1px solid var(--line); border-radius: .65rem; background: transparent; color: var(--ink); text-align: left; cursor: pointer; } button:hover, button.selected { border-color: var(--accent); background: var(--accent-soft); } .flow-name { display: flex; flex-wrap: wrap; gap: .4rem; align-items: center; font-size: .88rem; font-weight: 700; } .arrow { color: var(--muted); } .flow-meta { display: flex; flex-wrap: wrap; gap: .8rem; color: var(--muted); font-size: .76rem; } .flow-meta span:first-child { color: var(--success); font-weight: 700; } .empty { color: var(--muted); }
</style>
