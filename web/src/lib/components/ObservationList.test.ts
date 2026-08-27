import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import ObservationList from './ObservationList.svelte';
import type { Observation } from '../model';

const observations: Observation[] = [
  {
    id: 'observation-1',
    type: 'tcp-retransmission-candidate',
    message: 'TCP segment appears to resend bytes already seen.',
    packetNumbers: [4, 5],
    limitation: 'Only packets in this capture were considered.',
  },
];

describe('ObservationList', () => {
  it('shows a clear empty state', () => {
    render(ObservationList, { props: { observations: [], onSelectPacket: () => {} } });
    expect(screen.getByRole('heading', { name: 'Observations' })).toBeVisible();
    expect(screen.getByText(/no additional observations/i)).toBeVisible();
  });

  it('shows neutral evidence and uses keyboard-accessible packet buttons', async () => {
    const onSelectPacket = vi.fn();
    render(ObservationList, { props: { observations, onSelectPacket } });
    expect(screen.getByText(observations[0].message)).toBeVisible();
    expect(screen.getByText(observations[0].limitation)).toBeVisible();
    const evidence = screen.getByRole('button', {
      name: `View evidence packet 5 for ${observations[0].message}`,
    });
    await fireEvent.click(evidence);
    expect(onSelectPacket).toHaveBeenCalledWith(5);
  });
});
