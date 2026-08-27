<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { resolve } from '$app/paths';
  import CaptureOverview from '$lib/components/CaptureOverview.svelte';
  import CapturePicker from '$lib/components/CapturePicker.svelte';
  import ConversationList from '$lib/components/ConversationList.svelte';
  import PacketDetails from '$lib/components/PacketDetails.svelte';
  import PacketTable from '$lib/components/PacketTable.svelte';
  import TcpSequence from '$lib/components/TcpSequence.svelte';
  import { createCaptureStore, type CaptureState, type CaptureStore } from '$lib/capture-store';
  import { ParserClient } from '$lib/worker/parser-client';
  import type { CaptureDocument } from '$lib/model';

  let captureState = $state<CaptureState>({ status: 'empty' });
  let captureStore: CaptureStore | null = null;
  let selectedFlowId = $state('');
  let learningMode = $state(true);
  let isBrowser = $state(false);
  let focusedFileName = $state<string | null>(null);
  const document = $derived<CaptureDocument | null>(
    captureState.status === 'ready' ? captureState.document : null,
  );
  const selectedPacket = $derived.by(() => {
    const state = captureState;
    if (state.status !== 'ready') return undefined;
    return (
      state.document.packets.find((packet) => packet.id === state.selectedPacketId) ??
      state.document.packets[0]
    );
  });
  const selectedFlow = $derived(
    document?.flows.find((flow) => flow.id === selectedFlowId) ?? document?.flows[0],
  );
  const selectedTcpFlow = $derived(selectedFlow?.protocol === 'TCP' ? selectedFlow : undefined);

  onMount(() => {
    isBrowser = true;
    const parser = new ParserClient();
    captureStore = createCaptureStore(parser);
    let lastReadyDocument: CaptureDocument | null = null;
    const unsubscribe = captureStore.subscribe((next) => {
      captureState = next;
      if (next.status !== 'ready') {
        lastReadyDocument = null;
      } else if (next.document !== lastReadyDocument) {
        lastReadyDocument = next.document;
        selectedFlowId = next.document.flows[0]?.id ?? '';
      }
    });
    return () => {
      unsubscribe();
      void captureStore?.dispose();
      captureStore = null;
    };
  });

  $effect(() => {
    if (captureState.status === 'loading') focusedFileName = null;
    if (captureState.status !== 'ready' || focusedFileName === captureState.fileName) return;
    focusedFileName = captureState.fileName;
    void tick().then(() => {
      if (captureState.status === 'ready' && captureState.fileName === focusedFileName) {
        globalThis.document?.getElementById('overview-title')?.focus();
      }
    });
  });

  function handleFile(file: File) {
    void captureStore?.selectFile(file);
  }

  function selectPacket(id: string) {
    captureStore?.selectPacket(id);
  }
</script>

<svelte:head><title>WireLens · Capture inspector</title></svelte:head>

<a class="skip-link" href="#main-content">Skip to evidence</a>
<header class="topbar">
  <a class="brand" href={resolve('/')} aria-label="WireLens home"
    ><span class="brand-mark" aria-hidden="true">W</span><span>WireLens</span></a
  >
  <div class="top-actions">
    <span class="privacy-state"><span aria-hidden="true">●</span> Local only</span><button
      class="learning-toggle"
      type="button"
      aria-pressed={learningMode}
      onclick={() => (learningMode = !learningMode)}
      >Learning mode {learningMode ? 'on' : 'off'}</button
    >
  </div>
</header>

<main
  id="main-content"
  class="shell"
  data-browser={isBrowser ? 'ready' : 'static'}
  aria-busy={captureState.status === 'loading'}
>
  <section class="intro">
    <div>
      <p class="eyebrow">Packet capture inspector</p>
      <h1>See what happened<br /><em>in the wire.</em></h1>
      <p class="intro-copy">
        WireLens turns a capture file into a clear, evidence-based story of packets, protocols, and
        conversations.
      </p>
    </div>
    <div class="intro-note">
      <span class="note-mark" aria-hidden="true">✓</span>
      <p><strong>Private by design</strong><br />Your file stays in this browser.</p>
    </div>
  </section>
  <CapturePicker onFile={handleFile} captureStatus={captureState.status} />
  {#if captureState.status === 'loading'}
    <p class="processing" role="status" aria-live="polite">
      Reading {captureState.fileName} locally…
    </p>
  {:else if captureState.status === 'error'}
    <div class="parse-error" role="alert">
      <strong>Could not read {captureState.fileName ?? 'this capture'}.</strong>
      <span>{captureState.error.message}</span>
    </div>
  {/if}
  {#if document}
    <nav class="section-nav" aria-label="Capture sections">
      <span>Jump to</span><a href={resolve('/#overview')}>Overview</a><a
        href={resolve('/#conversations')}>Conversations</a
      ><a href={resolve('/#packets')}>Packets</a>
    </nav>
  {/if}
  {#if document}
    <div class="section-stack">
      <CaptureOverview {document} />
      <div class="split">
        <ConversationList
          flows={document.flows}
          endpoints={document.endpoints}
          {selectedFlowId}
          onSelect={(id) => (selectedFlowId = id)}
        />
        {#if selectedTcpFlow}<TcpSequence {document} flow={selectedTcpFlow} />{:else if selectedFlow}<section class="udp-note" aria-label="UDP flow"><strong>UDP datagrams</strong><p>This flow has no TCP sequence handshake.</p></section>{/if}
      </div>
      <div class="split packet-split">
        <PacketTable
          {document}
          selectedPacketId={captureState.status === 'ready'
            ? (captureState.selectedPacketId ?? '')
            : ''}
          onSelect={selectPacket}
        />
        {#if selectedPacket}<PacketDetails packet={selectedPacket} {learningMode} />{/if}
      </div>
    </div>
  {/if}
</main>

<footer>
  <span>WireLens v1 · local capture inspector</span><span
    >No upload · No data leaves this device</span
  >
</footer>

<style>
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    max-width: 1180px;
    margin: 0 auto;
    padding: 1.25rem 1.5rem;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    color: var(--ink);
    font-size: 1.05rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    text-decoration: none;
  }
  .brand-mark {
    display: grid;
    place-items: center;
    width: 1.75rem;
    height: 1.75rem;
    border-radius: 0.45rem;
    background: var(--accent);
    color: white;
    font-size: 0.85rem;
  }
  .top-actions {
    display: flex;
    align-items: center;
    gap: 0.8rem;
  }
  .privacy-state {
    color: var(--success);
    font-size: 0.76rem;
    font-weight: 700;
  }
  .privacy-state span {
    font-size: 0.8rem;
  }
  .learning-toggle {
    padding: 0.45rem 0.7rem;
    border: 1px solid var(--line-strong);
    border-radius: 0.4rem;
    background: var(--surface);
    color: var(--ink);
    font-size: 0.76rem;
    font-weight: 700;
    cursor: pointer;
  }
  .shell {
    display: grid;
    gap: 2rem;
    max-width: 1180px;
    margin: 0 auto;
    padding: 2rem 1.5rem 4rem;
  }
  .intro {
    display: flex;
    justify-content: space-between;
    align-items: end;
    gap: 2rem;
    padding: 2.5rem 0 1rem;
  }
  .eyebrow {
    margin: 0 0 0.6rem;
    color: var(--accent);
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.13em;
    text-transform: uppercase;
  }
  h1 {
    max-width: 720px;
    margin: 0;
    color: var(--ink);
    font-size: clamp(2.7rem, 8vw, 5.6rem);
    line-height: 0.95;
    letter-spacing: -0.07em;
  }
  h1 em {
    color: var(--accent);
    font-style: normal;
  }
  .intro-copy {
    max-width: 38rem;
    margin: 1.25rem 0 0;
    color: var(--muted);
    font-size: 1.05rem;
    line-height: 1.55;
  }
  .intro-note {
    display: flex;
    gap: 0.7rem;
    min-width: 13rem;
    padding: 1rem;
    border-top: 2px solid var(--accent);
    color: var(--muted);
    font-size: 0.8rem;
    line-height: 1.45;
  }
  .intro-note p {
    margin: 0;
  }
  .intro-note strong {
    color: var(--ink);
  }
  .note-mark {
    color: var(--accent);
    font-size: 1.15rem;
    font-weight: 800;
  }
  .section-nav {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.7rem;
    padding: 0.75rem 0;
    color: var(--muted);
    font-size: 0.76rem;
  }
  .section-nav span {
    margin-right: 0.25rem;
    font-weight: 700;
  }
  .section-nav a {
    color: var(--accent);
    font-weight: 700;
    text-decoration: none;
  }
  .section-nav a:hover {
    text-decoration: underline;
  }
  .section-stack {
    display: grid;
    gap: 1rem;
  }
  .split {
    display: grid;
    grid-template-columns: minmax(0, 0.7fr) minmax(0, 1.3fr);
    gap: 1rem;
  }
  .packet-split {
    grid-template-columns: minmax(0, 1.2fr) minmax(0, 0.8fr);
  }
  .processing,
  .parse-error {
    margin: 0;
    padding: 0.85rem 1rem;
    border: 1px solid var(--line);
    border-radius: 0.6rem;
    background: var(--surface);
    color: var(--muted);
    font-size: 0.85rem;
  }
  .parse-error {
    display: grid;
    gap: 0.25rem;
    border-color: var(--danger);
    color: var(--danger);
  }
  footer {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    max-width: 1180px;
    margin: 0 auto;
    padding: 1.5rem;
    border-top: 1px solid var(--line);
    color: var(--muted);
    font-size: 0.72rem;
  }
  @media (max-width: 760px) {
    .intro {
      display: grid;
      align-items: start;
    }
    .intro-note {
      max-width: 20rem;
    }
    .split,
    .packet-split {
      grid-template-columns: 1fr;
    }
  }
  @media (max-width: 520px) {
    .topbar {
      align-items: start;
      padding-inline: 1rem;
    }
    .top-actions {
      display: grid;
      justify-items: end;
      gap: 0.4rem;
    }
    .shell {
      padding-inline: 1rem;
    }
    footer {
      display: grid;
      padding-inline: 1rem;
    }
  }
</style>
