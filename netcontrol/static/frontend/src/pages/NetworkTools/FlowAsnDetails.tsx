import type { FlowTalker } from '@/api/networkTools';

import { flowAsnLabel } from './formatting';

export function FlowTalkerAddress({ row }: { row: FlowTalker }) {
  const label = flowAsnLabel(row);
  return (
    <>
      <code>{row.ip}</code>
      {label && <div className="text-muted">{label}</div>}
    </>
  );
}

export function FlowAsnAttribution() {
  return (
    <small className="text-muted">GeoLite2 data by <a href="https://www.maxmind.com/">MaxMind</a></small>
  );
}
