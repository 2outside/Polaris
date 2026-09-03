import type { ServerConfig } from '@/contracts/types';
import { sortServersByLatency } from '@/domain/server-latency-sort';
import type { ServerGroup } from '@/domain/server-grouping';

/** The list sort choices owned by the nodes toolbar. */
export type NodesListSortKey = 'default' | 'name' | 'lat' | 'proto';

/**
 * Derive the complete set of nodes addressed by the current toolbar state.
 *
 * This deliberately returns the full filtered result, not the render batch.
 * Selection, bulk actions, and the visible-scope speed test all operate on
 * this projection; only the render tail is sliced later by `useScrollBatch`.
 */
export function projectVisibleServers(
  activeGroup: ServerGroup | undefined,
  search: string,
  protoFilter: string,
  sortKey: NodesListSortKey,
  latencies: Readonly<Record<string, number | null>>,
): ServerConfig[] {
  if (!activeGroup) return [];

  let list = [...activeGroup.servers];
  const query = search.trim().toLowerCase();
  if (query) {
    list = list.filter(
      (server) =>
        server.name.toLowerCase().includes(query) ||
        server.address.toLowerCase().includes(query),
    );
  }
  if (protoFilter) {
    const protocol = protoFilter.toLowerCase();
    list = list.filter((server) => server.protocol.toLowerCase() === protocol);
  }

  // Direction is intentionally fixed: name/protocol A→Z and latency low→high.
  if (sortKey === 'name') {
    list.sort((a, b) => a.name.localeCompare(b.name));
  } else if (sortKey === 'lat') {
    // The domain comparator keeps missing measurements at the end.
    list = sortServersByLatency(list, (id) => latencies[id], 'asc');
  } else if (sortKey === 'proto') {
    list.sort((a, b) => a.protocol.localeCompare(b.protocol));
  }
  return list;
}
