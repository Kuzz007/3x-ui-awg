import { describe, it, expect, vi } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import HostFormModal from '@/pages/hosts/HostFormModal';
import { renderWithProviders } from './test-utils';

// HostFormModal reads node options via react-query (useNodesQuery), so it
// needs a QueryClientProvider on top of the shared ThemeProvider wrapper.
function renderModal() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  renderWithProviders(
    <QueryClientProvider client={queryClient}>
      <HostFormModal
        open
        mode="add"
        host={null}
        inboundOptions={[]}
        existingHosts={[]}
        save={vi.fn().mockResolvedValue(undefined)}
        onOpenChange={() => {}}
      />
    </QueryClientProvider>,
  );
}

describe('HostFormModal TLS field visibility', () => {
  it('shows Fingerprint and ALPN for the default Security ("same"), not just tls/reality', () => {
    renderModal();

    // Security defaults to 'same' with no host -- before the fix, showTls and
    // showTlsExtras both excluded 'same', so neither field ever rendered here.
    expect(document.body.textContent).toContain('Fingerprint');
    expect(document.body.textContent).toContain('ALPN');
  });
});
