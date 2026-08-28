import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import FilterSearch from './FilterSearch.svelte';

describe('FilterSearch', () => {
  it('provides named filter and approved-field search controls', async () => {
    const onFilterChange = vi.fn();
    const onSearchChange = vi.fn();
    render(FilterSearch, {
      props: {
        filterValue: '',
        searchValue: '',
        filterError: null,
        resultCount: 3,
        totalCount: 3,
        onFilterChange,
        onSearchChange,
      },
    });

    const filter = screen.getByRole('textbox', { name: 'Packet filter' });
    const search = screen.getByRole('searchbox', { name: 'Search packet facts' });
    await fireEvent.input(filter, { target: { value: 'tcp port:443' } });
    await fireEvent.input(search, { target: { value: 'example.test' } });
    expect(onFilterChange).toHaveBeenCalledWith('tcp port:443');
    expect(onSearchChange).toHaveBeenCalledWith('example.test');
    expect(screen.getByRole('status')).toHaveTextContent('Showing all 3 packets');
  });

  it('shows an inline grammar error without changing the last valid result count', () => {
    render(FilterSearch, {
      props: {
        filterValue: 'tcp or dns',
        searchValue: '',
        filterError: 'Unsupported filter token: or',
        resultCount: 2,
        totalCount: 5,
        onFilterChange: vi.fn(),
        onSearchChange: vi.fn(),
      },
    });
    expect(screen.getByRole('alert')).toHaveTextContent('Unsupported filter token: or');
    expect(screen.getByRole('status')).toHaveTextContent('Showing 2 of 5 packets');
    expect(screen.getByRole('textbox', { name: 'Packet filter' })).toHaveAttribute(
      'aria-invalid',
      'true',
    );
  });

  it('announces an empty result set', () => {
    render(FilterSearch, {
      props: {
        filterValue: 'udp',
        searchValue: 'missing',
        filterError: null,
        resultCount: 0,
        totalCount: 5,
        onFilterChange: vi.fn(),
        onSearchChange: vi.fn(),
      },
    });
    expect(screen.getByRole('status')).toHaveTextContent('No packets match');
  });
});
