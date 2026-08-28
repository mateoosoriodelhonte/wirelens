<script lang="ts">
  let {
    filterValue,
    searchValue,
    filterError,
    resultCount,
    totalCount,
    onFilterChange,
    onSearchChange,
  }: {
    filterValue: string;
    searchValue: string;
    filterError: string | null;
    resultCount: number;
    totalCount: number;
    onFilterChange: (value: string) => void;
    onSearchChange: (value: string) => void;
  } = $props();

  const resultMessage = $derived(
    resultCount === 0
      ? 'No packets match the current filter and search.'
      : resultCount === totalCount
        ? `Showing all ${totalCount} packets.`
        : `Showing ${resultCount} of ${totalCount} packets.`,
  );
</script>

<section class="tools" aria-labelledby="packet-tools-title">
  <div class="heading">
    <div>
      <p class="eyebrow">Narrow the evidence</p>
      <h2 id="packet-tools-title">Filter and search</h2>
    </div>
    <p class="result" role="status" aria-live="polite">{resultMessage}</p>
  </div>
  <div class="controls">
    <div class="field">
      <label for="packet-filter">Packet filter</label>
      <input
        id="packet-filter"
        value={filterValue}
        aria-invalid={filterError ? 'true' : undefined}
        aria-describedby={filterError ? 'filter-error' : 'filter-help'}
        placeholder="tcp port:443"
        oninput={(event) => onFilterChange(event.currentTarget.value)}
      />
      <small id="filter-help">Use protocol, ip:, and port: terms. Terms combine with AND.</small>
    </div>
    <div class="field">
      <label for="packet-search">Search packet facts</label>
      <input
        id="packet-search"
        type="search"
        value={searchValue}
        placeholder="Packet, IP, hostname, port, protocol, or safe path"
        oninput={(event) => onSearchChange(event.currentTarget.value)}
      />
      <small>Search uses sanitized facts only. It never searches raw packet bytes.</small>
    </div>
  </div>
  {#if filterError}<p id="filter-error" class="error" role="alert">{filterError}</p>{/if}
</section>

<style>
  .tools {
    display: grid;
    gap: 1rem;
    padding: 1.25rem 1.5rem;
    border: 1px solid var(--line);
    border-radius: 1rem;
    background: var(--surface);
  }
  .heading {
    display: flex;
    align-items: start;
    justify-content: space-between;
    gap: 1rem;
  }
  .eyebrow,
  h2,
  .result,
  .error {
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
  .result {
    color: var(--muted);
    font-size: 0.78rem;
    font-weight: 650;
    text-align: right;
  }
  .controls {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.85rem;
  }
  .field {
    display: grid;
    gap: 0.35rem;
  }
  label {
    color: var(--ink);
    font-size: 0.78rem;
    font-weight: 750;
  }
  input {
    width: 100%;
    box-sizing: border-box;
    padding: 0.65rem 0.7rem;
    border: 1px solid var(--line-strong);
    border-radius: 0.45rem;
    background: var(--surface-alt);
    color: var(--ink);
    font: inherit;
    font-weight: 500;
  }
  input:focus-visible {
    outline: 3px solid var(--accent-soft);
    border-color: var(--accent);
  }
  input[aria-invalid='true'] {
    border-color: var(--danger, #a33a3a);
  }
  small {
    color: var(--muted);
    font-size: 0.7rem;
    font-weight: 500;
    line-height: 1.4;
  }
  .error {
    padding: 0.65rem 0.75rem;
    border-left: 3px solid var(--danger, #a33a3a);
    background: var(--surface-alt);
    color: var(--ink);
    font-size: 0.78rem;
  }
  @media (max-width: 720px) {
    .heading {
      display: grid;
    }
    .result {
      text-align: left;
    }
    .controls {
      grid-template-columns: 1fr;
    }
  }
</style>
