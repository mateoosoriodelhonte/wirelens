import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import CaptureOverview from './CaptureOverview.svelte';
import { demoDocument } from '../demo-document';

describe('CaptureOverview', () => {
  it('shows the three-packet handshake overview', () => {
    render(CaptureOverview, { props: { document: demoDocument } });
    expect(screen.getByText('3 packets')).toBeInTheDocument();
    expect(screen.getByText('20 ms')).toBeInTheDocument();
  });
});
