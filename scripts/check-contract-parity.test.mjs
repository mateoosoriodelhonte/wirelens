import assert from 'node:assert/strict';
import test from 'node:test';

import { compareCaptureDocuments } from './check-contract-parity.mjs';

test('rejects a changed nested TCP acknowledgmentNumber', () => {
  const expected = {
    packets: [
      {
        layers: [
          {
            protocol: 'TCP',
            fields: [{ name: 'acknowledgmentNumber', value: '5001' }],
          },
        ],
      },
    ],
  };
  const actual = structuredClone(expected);
  actual.packets[0].layers[0].fields[0].value = '5002';

  assert.throws(
    () => compareCaptureDocuments(expected, actual),
    /\$\.packets\[0\]\.layers\[0\]\.fields\[0\]\.value/,
  );
});

test('accepts equal JSON values despite object key order', () => {
  assert.equal(
    compareCaptureDocuments(
      { contractVersion: '1.0.0', packets: [{ number: 1, id: 'packet-1' }] },
      { packets: [{ id: 'packet-1', number: 1 }], contractVersion: '1.0.0' },
    ),
    true,
  );
});
