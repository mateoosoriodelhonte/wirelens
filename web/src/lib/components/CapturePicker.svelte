<script lang="ts">
  let {
    onFile,
    captureStatus = 'empty',
  }: {
    onFile: (file: File) => void;
    captureStatus?: 'empty' | 'loading' | 'ready' | 'error';
  } = $props();
  let status = $state('No capture selected. Files stay on this device.');
  let error = $state('');
  let isDragging = $state(false);
  const visibleStatus = $derived(
    captureStatus === 'loading'
      ? 'Reading the selected capture locally…'
      : captureStatus === 'error'
        ? 'Capture could not be read. Choose another .pcap.'
        : status,
  );

  function selectFile(file: File | undefined) {
    if (!file) return;
    if (!/\.pcap$/i.test(file.name)) {
      error = 'Choose a .pcap file.';
      status = 'Capture type not supported.';
      return;
    }
    error = '';
    status = `${file.name} is ready to inspect locally.`;
    onFile(file);
  }

  function handleChange(event: Event) {
    selectFile((event.currentTarget as HTMLInputElement).files?.[0]);
  }

  function handleDrop(event: DragEvent) {
    event.preventDefault();
    isDragging = false;
    selectFile(event.dataTransfer?.files[0]);
  }
</script>

<section class="picker" aria-labelledby="picker-title">
  <div>
    <p class="eyebrow">Capture entry</p>
    <h2 id="picker-title">Inspect a capture on this device</h2>
    <p class="lede">WireLens reads a supported file in your browser. Nothing is uploaded.</p>
  </div>
  <label
    class:dragging={isDragging}
    class="drop-zone"
    ondragover={(event) => {
      event.preventDefault();
      isDragging = true;
    }}
    ondragleave={() => (isDragging = false)}
    ondrop={handleDrop}
  >
    <span class="drop-icon" aria-hidden="true">↥</span>
    <span class="drop-title">Choose a capture file</span>
    <span class="drop-help">.pcap · up to 64 MiB · drag and drop also works</span>
    <input
      aria-label="Capture file"
      type="file"
      accept=".pcap,application/vnd.tcpdump.pcap"
      onchange={handleChange}
    />
  </label>
  <p class="status" role="status">{visibleStatus}</p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</section>

<style>
  .picker {
    display: grid;
    gap: 1.25rem;
    padding: 1.5rem;
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 1rem;
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
    color: var(--ink);
    font-size: clamp(1.35rem, 3vw, 1.8rem);
    letter-spacing: -0.03em;
  }
  .lede,
  .drop-help,
  .status {
    margin: 0.4rem 0 0;
    color: var(--muted);
    font-size: 0.92rem;
  }
  .drop-zone {
    display: grid;
    justify-items: center;
    gap: 0.35rem;
    padding: 2rem 1rem;
    border: 1px dashed var(--line-strong);
    border-radius: 0.75rem;
    background: var(--surface-alt);
    text-align: center;
    cursor: pointer;
    transition:
      border-color 0.15s ease,
      background 0.15s ease;
  }
  .drop-zone:hover,
  .drop-zone.dragging {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .drop-zone:focus-within {
    outline: 3px solid color-mix(in srgb, var(--accent) 60%, white);
    outline-offset: 3px;
  }
  .drop-icon {
    display: grid;
    place-items: center;
    width: 2.5rem;
    height: 2.5rem;
    border-radius: 50%;
    background: var(--accent);
    color: white;
    font-size: 1.35rem;
  }
  .drop-title {
    color: var(--ink);
    font-weight: 700;
  }
  input {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
  }
  .error {
    margin: 0;
    color: var(--danger);
    font-weight: 600;
  }
  @media (prefers-reduced-motion: reduce) {
    .drop-zone {
      transition: none;
    }
  }
</style>
