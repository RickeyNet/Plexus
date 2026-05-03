/**
 * TopologyCanvas — lightweight SVG topology view for Phase B-2.
 *
 * Lays nodes out on a circle (deterministic, no physics engine) and draws
 * edges between them. Click a node to select it; clicking a second node
 * fires `onProposeLink` with both endpoints so the parent can prompt for
 * interface names. No drag, no zoom — those come later if anyone asks.
 *
 * Pure SVG keeps the bundle small (no vis-network / reactflow / d3 dep)
 * and avoids ResizeObserver / canvas portability headaches inside
 * PatternFly.
 */

import { useMemo, useState } from 'react';

import { LabDevice, LabTopologyLink } from '@/api/lab';

const CANVAS_W = 720;
const CANVAS_H = 420;
const NODE_RADIUS = 28;
const PADDING = 40;

export interface ProposedLink {
  a_device_id: number;
  b_device_id: number;
}

interface NodePos {
  id: number;
  x: number;
  y: number;
}

/**
 * Place N nodes evenly around a circle inset from the canvas edges.
 * Exposed for unit tests; the parent never calls it directly.
 */
export function circularLayout(
  ids: number[],
  width = CANVAS_W,
  height = CANVAS_H,
  padding = PADDING,
): NodePos[] {
  if (ids.length === 0) return [];
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.max(40, Math.min(width, height) / 2 - padding - NODE_RADIUS);
  if (ids.length === 1) {
    return [{ id: ids[0], x: cx, y: cy }];
  }
  return ids.map((id, i) => {
    const angle = (2 * Math.PI * i) / ids.length - Math.PI / 2;
    return {
      id,
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    };
  });
}

function statusColor(status: string | undefined): string {
  switch (status) {
    case 'running':
      return '#3e8635';
    case 'provisioning':
      return '#06c';
    case 'stopped':
    case 'destroyed':
      return '#6a6e73';
    case 'error':
      return '#c9190b';
    default:
      return '#8a8d90';
  }
}

interface Props {
  devices: LabDevice[];
  links: LabTopologyLink[];
  onProposeLink?: (proposed: ProposedLink) => void;
  onSelectDevice?: (deviceId: number | null) => void;
  selectedDeviceId?: number | null;
  /** Ids of links the parent wants to fade out (e.g. mid-deletion). */
  pendingRemoveLinkIds?: number[];
}

export function TopologyCanvas({
  devices,
  links,
  onProposeLink,
  onSelectDevice,
  selectedDeviceId = null,
  pendingRemoveLinkIds = [],
}: Props) {
  const [hoverId, setHoverId] = useState<number | null>(null);
  const [pendingFirst, setPendingFirst] = useState<number | null>(null);

  const positions = useMemo(
    () => circularLayout(devices.map((d) => d.id)),
    [devices],
  );
  const posById = useMemo(() => {
    const m = new Map<number, NodePos>();
    for (const p of positions) m.set(p.id, p);
    return m;
  }, [positions]);

  if (devices.length === 0) {
    return (
      <div
        style={{
          width: '100%',
          height: 200,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#6a6e73',
          fontStyle: 'italic',
          border: '1px dashed #ccc',
          borderRadius: 4,
        }}
      >
        Add member devices to see the canvas.
      </div>
    );
  }

  const handleNodeClick = (deviceId: number) => {
    onSelectDevice?.(deviceId === selectedDeviceId ? null : deviceId);
    if (!onProposeLink) return;
    if (pendingFirst === null) {
      setPendingFirst(deviceId);
      return;
    }
    if (pendingFirst === deviceId) {
      // Deselect when the same node is clicked twice.
      setPendingFirst(null);
      return;
    }
    onProposeLink({ a_device_id: pendingFirst, b_device_id: deviceId });
    setPendingFirst(null);
  };

  const pendingRemove = new Set(pendingRemoveLinkIds);

  return (
    <div style={{ position: 'relative' }}>
      <svg
        viewBox={`0 0 ${CANVAS_W} ${CANVAS_H}`}
        style={{
          width: '100%',
          maxWidth: CANVAS_W,
          height: 'auto',
          background: 'var(--pf-v6-global--BackgroundColor--100, #fff)',
          border: '1px solid #ccc',
          borderRadius: 4,
        }}
        role="img"
        aria-label="Topology canvas"
      >
        {/* Edges first so nodes draw on top */}
        {links.map((link) => {
          const a = posById.get(link.a_device_id);
          const b = posById.get(link.b_device_id);
          if (!a || !b) return null;
          const opacity = pendingRemove.has(link.id) ? 0.3 : 1;
          // Place endpoint labels along the line, biased toward the source.
          const labelOffset = 0.22;
          const aLabelX = a.x + (b.x - a.x) * labelOffset;
          const aLabelY = a.y + (b.y - a.y) * labelOffset;
          const bLabelX = b.x + (a.x - b.x) * labelOffset;
          const bLabelY = b.y + (a.y - b.y) * labelOffset;
          return (
            <g key={link.id} opacity={opacity}>
              <line
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke="#6a6e73"
                strokeWidth={2}
              />
              <text
                x={aLabelX}
                y={aLabelY}
                fontSize={11}
                fill="#151515"
                textAnchor="middle"
                dominantBaseline="central"
                style={{ pointerEvents: 'none', paintOrder: 'stroke', stroke: '#fff', strokeWidth: 3 }}
              >
                {link.a_endpoint}
              </text>
              <text
                x={bLabelX}
                y={bLabelY}
                fontSize={11}
                fill="#151515"
                textAnchor="middle"
                dominantBaseline="central"
                style={{ pointerEvents: 'none', paintOrder: 'stroke', stroke: '#fff', strokeWidth: 3 }}
              >
                {link.b_endpoint}
              </text>
            </g>
          );
        })}

        {/* Nodes */}
        {devices.map((d) => {
          const p = posById.get(d.id);
          if (!p) return null;
          const isSelected = selectedDeviceId === d.id || pendingFirst === d.id;
          const isHover = hoverId === d.id;
          const fill = statusColor(d.runtime_status);
          return (
            <g
              key={d.id}
              transform={`translate(${p.x}, ${p.y})`}
              style={{ cursor: onProposeLink || onSelectDevice ? 'pointer' : 'default' }}
              onMouseEnter={() => setHoverId(d.id)}
              onMouseLeave={() => setHoverId((id) => (id === d.id ? null : id))}
              onClick={() => handleNodeClick(d.id)}
            >
              <circle
                r={NODE_RADIUS}
                fill={fill}
                stroke={isSelected ? '#06c' : isHover ? '#151515' : '#fff'}
                strokeWidth={isSelected ? 4 : 2}
              />
              <text
                fontSize={11}
                fill="#fff"
                textAnchor="middle"
                dominantBaseline="central"
                style={{ pointerEvents: 'none', fontWeight: 600 }}
              >
                {d.hostname.slice(0, 6)}
              </text>
              <text
                y={NODE_RADIUS + 14}
                fontSize={11}
                fill="#151515"
                textAnchor="middle"
                style={{ pointerEvents: 'none' }}
              >
                {d.hostname}
              </text>
            </g>
          );
        })}
      </svg>

      {pendingFirst !== null && onProposeLink && (
        <div
          style={{
            position: 'absolute',
            top: 8,
            left: 8,
            background: 'rgba(0,98,204,0.85)',
            color: '#fff',
            padding: '4px 10px',
            borderRadius: 4,
            fontSize: '0.85em',
          }}
        >
          Click a second node to link to{' '}
          <strong>
            {devices.find((d) => d.id === pendingFirst)?.hostname ?? '?'}
          </strong>{' '}
          · click it again to cancel
        </div>
      )}

      {hoverId !== null && (() => {
        const d = devices.find((x) => x.id === hoverId);
        if (!d) return null;
        return (
          <div
            style={{
              position: 'absolute',
              top: 8,
              right: 8,
              background: 'rgba(21,21,21,0.85)',
              color: '#fff',
              padding: '6px 10px',
              borderRadius: 4,
              fontSize: '0.8em',
              maxWidth: 240,
            }}
          >
            <strong>{d.hostname}</strong>
            <div>
              kind: {d.runtime_node_kind || '—'} · status: {d.runtime_status || '—'}
            </div>
            <div>image: {d.runtime_image || '—'}</div>
            <div>mgmt: {d.runtime_mgmt_address || '—'}</div>
          </div>
        );
      })()}
    </div>
  );
}
