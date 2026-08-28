<script lang="ts">
  import type { ByteRange } from '@wirelens/schema';
  import { validateByteRange, type ByteRangeValidation } from '../hex-range';

  export type HexViewBytes = ArrayBuffer | Uint8Array;
  export type HexViewProps = {
    bytes?: HexViewBytes | null;
    loading?: boolean;
    error?: string | null;
    fieldRange?: ByteRange | null;
  };

  let { bytes = null, loading = false, error = null, fieldRange = null }: HexViewProps = $props();

  const packetBytes = $derived(toBytes(bytes));
  const range = $derived(validateByteRange(fieldRange, packetBytes?.byteLength ?? 0));
  const rows = $derived(packetBytes ? makeRows(packetBytes) : []);

  function toBytes(value: HexViewBytes | null): Uint8Array | null {
    if (value === null) return null;
    return value instanceof Uint8Array ? value : new Uint8Array(value);
  }

  function makeRows(value: Uint8Array): Array<{ offset: number; values: Uint8Array }> {
    const result: Array<{ offset: number; values: Uint8Array }> = [];
    for (let offset = 0; offset < value.byteLength; offset += 16) {
      result.push({ offset, values: value.slice(offset, offset + 16) });
    }
    return result;
  }

  function formatByte(value: number): string {
    return value.toString(16).padStart(2, '0');
  }

  function printable(value: number): string {
    return value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : '.';
  }

  function formatOffset(value: number): string {
    return value.toString(16).padStart(8, '0');
  }

  const separator = ' ';

  function isSelected(offset: number, validation: ByteRangeValidation): boolean {
    return (
      validation.kind === 'valid' && offset >= validation.start && offset < validation.endExclusive
    );
  }

  function rangeMessage(validation: ByteRangeValidation): string {
    if (validation.kind === 'none')
      return 'Field range is not available. Bytes are shown without highlighting.';
    return 'Field range is outside packet bytes. Bytes are shown without highlighting.';
  }
</script>

{#if error}
  <p class="state error" role="alert">{error}</p>
{:else if loading}
  <p class="state" role="status">Loading selected packet bytes…</p>
{:else if packetBytes === null}
  <p class="state" role="status">Select a packet to inspect its bytes.</p>
{:else if packetBytes.byteLength === 0}
  <p class="state" role="status">No packet bytes are available.</p>
{:else}
  <section class="hex-view" aria-labelledby="hex-view-title">
    <div class="heading">
      <h2 id="hex-view-title">Selected packet bytes</h2>
      <span>{packetBytes.byteLength} bytes</span>
    </div>
    {#if range.kind === 'valid'}
      <p class="range-note" id="hex-range-note">
        Selected field: bytes {range.start}–{range.endExclusive - 1}.
      </p>
    {:else}
      <p
        class="range-note"
        class:warning={range.kind === 'invalid'}
        id="hex-range-note"
        role="status"
      >
        {rangeMessage(range)}
      </p>
    {/if}
    <p class="selection-help" id="hex-selection-help">
      Selected bytes are marked in the hex column. Use Tab to move between rows.
    </p>
    <table aria-label="Selected packet bytes" aria-describedby="hex-range-note hex-selection-help">
      <caption class="visually-hidden"
        >Selected packet bytes in hexadecimal and printable ASCII.</caption
      >
      <thead>
        <tr>
          <th scope="col">Offset</th>
          <th scope="col">Hex bytes</th>
          <th scope="col">ASCII</th>
        </tr>
      </thead>
      <tbody>
        {#each rows as row (row.offset)}
          <tr
            class="hex-row"
            tabindex="0"
            aria-label={`Offset ${row.offset}, ${row.values.byteLength} bytes`}
          >
            <th scope="row">{formatOffset(row.offset)}</th>
            <td class="hex-bytes">
              {#each row.values as value, index (row.offset + index)}
                {@const offset = row.offset + index}
                {#if isSelected(offset, range)}
                  <mark data-offset={offset} aria-label={`Byte ${offset}, selected field`}
                    >{formatByte(value)}</mark
                  >
                {:else}
                  <span data-offset={offset}>{formatByte(value)}</span>
                {/if}{#if index < row.values.byteLength - 1}{separator}{/if}
              {/each}
            </td>
            <td class="ascii" aria-label="Printable ASCII alternative">
              {#each row.values as value, index (row.offset + index)}
                <span class:selected={isSelected(row.offset + index, range)}
                  >{printable(value)}</span
                >
              {/each}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
{/if}

<style>
  .state {
    margin: 0;
    padding: 1rem;
    border: 1px solid var(--line);
    border-radius: 0.65rem;
    background: var(--surface-alt);
    color: var(--muted);
  }
  .state.error {
    border-color: var(--danger);
    color: var(--danger);
  }
  .hex-view {
    display: grid;
    gap: 0.75rem;
    min-width: 0;
    overflow-x: auto;
    padding: 1rem;
    border: 1px solid var(--line);
    border-radius: 0.75rem;
    background: var(--surface);
  }
  .heading {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 1rem;
  }
  h2 {
    margin: 0;
    font-size: 1.05rem;
  }
  .heading > span,
  .selection-help {
    color: var(--muted);
    font-size: 0.78rem;
  }
  .range-note,
  .selection-help {
    margin: 0;
  }
  .range-note {
    color: var(--success);
    font-size: 0.8rem;
    font-weight: 700;
  }
  .range-note.warning {
    color: var(--danger);
  }
  table {
    width: 100%;
    min-width: 34rem;
    border-collapse: collapse;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.78rem;
  }
  th,
  td {
    padding: 0.45rem 0.5rem;
    border-top: 1px solid var(--line);
    text-align: left;
    vertical-align: top;
  }
  thead th {
    color: var(--muted);
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  tbody th {
    width: 6rem;
    color: var(--muted);
    font-weight: 600;
  }
  .hex-bytes {
    white-space: pre;
    letter-spacing: 0.04em;
  }
  mark {
    padding: 0.08rem 0.12rem;
    border: 1px solid var(--accent);
    border-radius: 0.2rem;
    background: var(--accent-soft);
    color: var(--ink);
    font-weight: 800;
  }
  .ascii {
    min-width: 10rem;
    white-space: pre;
    letter-spacing: 0.08em;
  }
  .ascii span.selected {
    text-decoration: underline;
    text-decoration-thickness: 2px;
    text-underline-offset: 0.15rem;
  }
  .hex-row:focus-visible {
    outline: 3px solid color-mix(in srgb, var(--accent) 60%, white);
    outline-offset: -2px;
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
  @media (max-width: 42rem) {
    .heading {
      align-items: start;
    }
  }
</style>
