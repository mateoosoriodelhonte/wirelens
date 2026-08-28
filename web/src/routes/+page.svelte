<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { resolve } from '$app/paths';
  import CaptureOverview from '$lib/components/CaptureOverview.svelte';
  import CapturePicker from '$lib/components/CapturePicker.svelte';
  import ConversationList from '$lib/components/ConversationList.svelte';
  import DnsExchangeList from '$lib/components/DnsExchangeList.svelte';
  import FilterSearch from '$lib/components/FilterSearch.svelte';
  import HexView from '$lib/components/HexView.svelte';
  import HttpExchangeList from '$lib/components/HttpExchangeList.svelte';
  import ObservationList from '$lib/components/ObservationList.svelte';
  import PacketDetails from '$lib/components/PacketDetails.svelte';
  import PacketTable from '$lib/components/PacketTable.svelte';
  import TcpSequence from '$lib/components/TcpSequence.svelte';
  import TlsHandshakeList from '$lib/components/TlsHandshakeList.svelte';
  import { createCaptureStore, type CaptureState, type CaptureStore } from '$lib/capture-store';
  import { filterPackets } from '$lib/filter';
  import { buildSearchIndex, searchPackets } from '$lib/search';
  import { ParserClient } from '$lib/worker/parser-client';
  import type { ByteRange, CaptureDocument, Packet } from '$lib/model';

  let captureState = $state<CaptureState>({ status: 'empty' });
  let captureStore: CaptureStore | null = null;
  let selectedFlowId = $state('');
  let learningMode = $state(true);
  let isBrowser = $state(false);
  let focusedFileName = $state<string | null>(null);
  let activeSection = $state('overview');
  let filterValue = $state('');
  let searchValue = $state('');
  let filterError = $state<string | null>(null);
  let lastValidFilterPacketIds = $state<string[] | null>(null);
  let selectedByteRange = $state<ByteRange | null>(null);
  const sections = [
    ['overview', 'Overview'],
    ['conversations', 'Conversations'],
    ['dns', 'DNS'],
    ['http', 'HTTP'],
    ['tls', 'TLS'],
    ['observations', 'Observations'],
    ['packets', 'Packets'],
  ] as const;
  const document = $derived<CaptureDocument | null>(
    captureState.status === 'ready' ? captureState.document : null,
  );
  const searchIndex = $derived(document ? buildSearchIndex(document) : null);
  const visiblePackets = $derived.by((): Packet[] => {
    if (!document) return [];
    const filterIds = new Set(lastValidFilterPacketIds ?? document.packets.map(({ id }) => id));
    const filtered = document.packets.filter(({ id }) => filterIds.has(id));
    if (!searchValue.trim() || !searchIndex) return filtered;
    const searchPacketNumbers = new Set(
      searchPackets(searchIndex, searchValue).map(({ packetNumber }) => packetNumber),
    );
    return filtered.filter(({ number }) => searchPacketNumbers.has(number));
  });
  const selectedPacket = $derived.by(() => {
    const state = captureState;
    if (state.status !== 'ready') return undefined;
    return visiblePackets.find((packet) => packet.id === state.selectedPacketId);
  });
  const selectedFlow = $derived(
    document?.flows.find((flow) => flow.id === selectedFlowId) ?? document?.flows[0],
  );
  const selectedTcpFlow = $derived(selectedFlow?.protocol === 'TCP' ? selectedFlow : undefined);
  const dnsObservations = $derived(
    document?.observations.filter(
      (observation) => observation.type === 'dns-error' || observation.type === 'slow-dns',
    ) ?? [],
  );
  const otherObservations = $derived(
    document?.observations.filter(
      (observation) => observation.type !== 'dns-error' && observation.type !== 'slow-dns',
    ) ?? [],
  );

  onMount(() => {
    isBrowser = true;
    const setSectionFromHash = () => {
      const hashSection = globalThis.location.hash.slice(1);
      if (sections.some(([id]) => id === hashSection)) activeSection = hashSection;
    };
    setSectionFromHash();
    globalThis.addEventListener('hashchange', setSectionFromHash);
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
        filterValue = '';
        searchValue = '';
        filterError = null;
        lastValidFilterPacketIds = next.document.packets.map(({ id }) => id);
        selectedByteRange = null;
      }
    });
    return () => {
      globalThis.removeEventListener('hashchange', setSectionFromHash);
      unsubscribe();
      void captureStore?.dispose();
      captureStore = null;
    };
  });

  $effect(() => {
    if (!isBrowser || !document || !('IntersectionObserver' in globalThis)) return;
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible?.target.id) activeSection = visible.target.id;
      },
      { rootMargin: '-15% 0px -65% 0px', threshold: [0, 0.25, 0.5, 1] },
    );
    for (const [id] of sections) {
      const section = globalThis.document.getElementById(id);
      if (section) observer.observe(section);
    }
    return () => observer.disconnect();
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
    selectedByteRange = null;
    captureStore?.selectPacket(id);
  }

  function visiblePacketIds(filterIds: readonly string[], query: string): string[] {
    if (!document) return [];
    const allowed = new Set(filterIds);
    if (!query.trim())
      return document.packets.filter(({ id }) => allowed.has(id)).map(({ id }) => id);
    const index = searchIndex ?? buildSearchIndex(document);
    const matches = new Set(searchPackets(index, query).map(({ packetNumber }) => packetNumber));
    return document.packets
      .filter(({ id, number }) => allowed.has(id) && matches.has(number))
      .map(({ id }) => id);
  }

  function selectFirstVisibleIfNeeded(ids: readonly string[]) {
    if (captureState.status !== 'ready') return;
    if (captureState.selectedPacketId && ids.includes(captureState.selectedPacketId)) return;
    if (ids[0]) selectPacket(ids[0]);
  }

  function handleFilterChange(value: string) {
    filterValue = value;
    if (!document) return;
    const result = filterPackets(document, value);
    if (!result.ok) {
      filterError = result.error.message;
      return;
    }
    filterError = null;
    lastValidFilterPacketIds = result.packets.map(({ id }) => id);
    selectFirstVisibleIfNeeded(visiblePacketIds(lastValidFilterPacketIds, searchValue));
  }

  function handleSearchChange(value: string) {
    searchValue = value;
    if (!document) return;
    const filterIds = lastValidFilterPacketIds ?? document.packets.map(({ id }) => id);
    selectFirstVisibleIfNeeded(visiblePacketIds(filterIds, value));
  }

  function resetInspectionTools() {
    if (!document) return;
    filterValue = '';
    searchValue = '';
    filterError = null;
    lastValidFilterPacketIds = document.packets.map(({ id }) => id);
  }

  async function selectEvidencePacket(packetNumber: number) {
    const packet = document?.packets.find((candidate) => candidate.number === packetNumber);
    if (!packet) return;
    resetInspectionTools();
    if (packet.flowId) selectedFlowId = packet.flowId;
    selectPacket(packet.id);
    await tick();
    globalThis.document?.getElementById('details-title')?.focus();
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
      <span>Jump to</span>
      {#each sections as [id, label] (id)}
        <a
          class:active={activeSection === id}
          href={resolve(`/#${id}`)}
          aria-current={activeSection === id ? 'location' : undefined}
          onclick={() => (activeSection = id)}>{label}</a
        >
      {/each}
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
        {#if selectedTcpFlow}<TcpSequence
            {document}
            flow={selectedTcpFlow}
          />{:else if selectedFlow}<section class="udp-note" aria-label="UDP flow">
            <strong>UDP datagrams</strong>
            <p>This flow has no TCP sequence handshake.</p>
          </section>{/if}
      </div>
      <DnsExchangeList
        exchanges={document.dnsExchanges}
        observations={dnsObservations}
        onSelectPacket={selectEvidencePacket}
      />
      <HttpExchangeList exchanges={document.httpExchanges} onSelectPacket={selectEvidencePacket} />
      <TlsHandshakeList handshakes={document.tlsHandshakes} onSelectPacket={selectEvidencePacket} />
      <ObservationList observations={otherObservations} onSelectPacket={selectEvidencePacket} />
      <FilterSearch
        {filterValue}
        {searchValue}
        {filterError}
        resultCount={visiblePackets.length}
        totalCount={document.packets.length}
        onFilterChange={handleFilterChange}
        onSearchChange={handleSearchChange}
      />
      <div class="split packet-split">
        <PacketTable
          {document}
          packets={visiblePackets}
          selectedPacketId={captureState.status === 'ready'
            ? (captureState.selectedPacketId ?? '')
            : ''}
          onSelect={selectPacket}
        />
        <div class="inspection-stack">
          {#if selectedPacket}
            <PacketDetails
              packet={selectedPacket}
              {learningMode}
              {selectedByteRange}
              onSelectByteRange={(range) => (selectedByteRange = range)}
            />
            <HexView
              bytes={captureState.status === 'ready' &&
              captureState.packetBytes.status === 'ready' &&
              captureState.packetBytes.packetId === selectedPacket.id
                ? captureState.packetBytes.buffer
                : null}
              loading={captureState.status === 'ready' &&
                captureState.packetBytes.status === 'loading' &&
                captureState.packetBytes.packetId === selectedPacket.id}
              error={captureState.status === 'ready' &&
              captureState.packetBytes.status === 'error' &&
              captureState.packetBytes.packetId === selectedPacket.id
                ? captureState.packetBytes.error.message
                : null}
              fieldRange={selectedByteRange}
            />
          {:else}
            <section class="no-packets" aria-label="No matching packet details">
              <strong>No matching packet is selected.</strong>
              <p>Clear or change the filter and search to inspect packet details.</p>
            </section>
          {/if}
        </div>
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
  .section-nav a.active {
    color: var(--ink);
    text-decoration: underline;
    text-underline-offset: 0.25em;
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
  .inspection-stack {
    display: grid;
    align-content: start;
    gap: 1rem;
    min-width: 0;
  }
  .no-packets {
    padding: 1.25rem;
    border: 1px solid var(--line);
    border-radius: 1rem;
    background: var(--surface);
    color: var(--muted);
  }
  .no-packets p {
    margin: 0.35rem 0 0;
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
