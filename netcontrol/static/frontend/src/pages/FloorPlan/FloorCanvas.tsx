import { CSSProperties, useEffect, useRef, useState } from 'react';

import {
  FloorPlacement,
  GeoFloor,
  floorImageUrl,
  useUpsertFloorPlacement,
} from '@/api/floorPlan';

import { statusColor } from './statusColor';

interface Props {
  floor: GeoFloor;
  placements: FloorPlacement[];
  placeMode: boolean;
}

/**
 * Renders the floor-plan image with positioned device pins overlaid on top.
 *
 * Pin coordinates are normalized 0..1 against the *displayed* image
 * dimensions, so percentage-based CSS positioning survives any scaling the
 * browser does to fit the canvas area.
 *
 * Two interactions:
 *   * In placeMode, existing pins are draggable via mousedown→mousemove→
 *     mouseup. The final position is persisted via upsertFloorPlacement.
 *   * In placeMode, the layer accepts HTML5 drag/drop from the unplaced-
 *     devices sidebar; on drop the host id is read from the dataTransfer
 *     payload and a new placement is created.
 *
 * Outside placeMode the layer is non-interactive (pointer-events: none).
 */
export function FloorCanvas({ floor, placements, placeMode }: Props) {
  const imgRef = useRef<HTMLImageElement | null>(null);
  // Cache-bust the image URL when the floor changes so a fresh upload is
  // visible without forcing the browser to disregard cache for unrelated
  // requests.
  const [cacheKey] = useState(() => Date.now());
  const upsert = useUpsertFloorPlacement();
  const [draggedHostId, setDraggedHostId] = useState<number | null>(null);
  const [dragPos, setDragPos] = useState<{ x: number; y: number } | null>(null);

  // Drag of an existing pin: track on document so the cursor can leave the
  // pin element without breaking the gesture.
  useEffect(() => {
    if (draggedHostId === null) return;

    const onMove = (e: MouseEvent) => {
      const img = imgRef.current;
      if (!img) return;
      const rect = img.getBoundingClientRect();
      const x = clamp01((e.clientX - rect.left) / rect.width);
      const y = clamp01((e.clientY - rect.top) / rect.height);
      setDragPos({ x, y });
    };

    const onUp = async () => {
      const finalPos = dragPosRef.current;
      const hostId = draggedHostId;
      setDraggedHostId(null);
      setDragPos(null);
      if (finalPos && hostId !== null) {
        try {
          await upsert.mutateAsync({
            floorId: floor.id,
            hostId,
            x_pct: finalPos.x,
            y_pct: finalPos.y,
          });
        } catch (err) {
          alert(
            'Failed to save pin position: ' +
              (err instanceof Error ? err.message : String(err)),
          );
        }
      }
    };

    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    return () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draggedHostId, floor.id]);

  // Mirror dragPos into a ref so the mouseup handler reads the latest value.
  // (Closure captures the initial state, which is null.)
  const dragPosRef = useRef<{ x: number; y: number } | null>(null);
  useEffect(() => {
    dragPosRef.current = dragPos;
  }, [dragPos]);

  if (!floor.image_filename) {
    return <EmptyCanvas message='No floor plan image. Use "Upload Floor Plan" to add one.' />;
  }

  return (
    <div style={{ position: 'relative', width: 'fit-content' }}>
      <img
        ref={imgRef}
        src={floorImageUrl(floor.id, cacheKey)}
        alt="Floor plan"
        draggable={false}
        style={{
          display: 'block',
          maxWidth: '100%',
          userSelect: 'none',
          WebkitUserDrag: 'none',
        } as CSSProperties}
      />
      <div
        style={{
          position: 'absolute',
          inset: 0,
          pointerEvents: placeMode ? 'auto' : 'none',
        }}
        onDragOver={(e) => {
          if (!placeMode) return;
          e.preventDefault();
        }}
        onDrop={async (e) => {
          if (!placeMode) return;
          e.preventDefault();
          const hostIdRaw = e.dataTransfer.getData('text/plain');
          const hostId = parseInt(hostIdRaw, 10);
          if (!hostId || Number.isNaN(hostId)) return;
          const img = imgRef.current;
          if (!img) return;
          const rect = img.getBoundingClientRect();
          const x = clamp01((e.clientX - rect.left) / rect.width);
          const y = clamp01((e.clientY - rect.top) / rect.height);
          try {
            await upsert.mutateAsync({
              floorId: floor.id,
              hostId,
              x_pct: x,
              y_pct: y,
            });
          } catch (err) {
            alert(
              'Failed to place device: ' +
                (err instanceof Error ? err.message : String(err)),
            );
          }
        }}
      >
        {placements.map((p) => {
          const isDragging = draggedHostId === p.host_id;
          const x = isDragging && dragPos ? dragPos.x : p.x_pct;
          const y = isDragging && dragPos ? dragPos.y : p.y_pct;
          return (
            <Pin
              key={p.host_id}
              placement={p}
              x={x}
              y={y}
              placeMode={placeMode}
              dragging={isDragging}
              onMouseDown={() => {
                if (!placeMode) return;
                setDraggedHostId(p.host_id);
                setDragPos({ x: p.x_pct, y: p.y_pct });
              }}
            />
          );
        })}
      </div>
    </div>
  );
}

function Pin({
  placement,
  x,
  y,
  placeMode,
  dragging,
  onMouseDown,
}: {
  placement: FloorPlacement;
  x: number;
  y: number;
  placeMode: boolean;
  dragging: boolean;
  onMouseDown: () => void;
}) {
  const color = statusColor(placement.status);
  return (
    <div
      data-host-id={placement.host_id}
      title={`${placement.hostname} (${placement.ip_address ?? ''})`}
      onMouseDown={onMouseDown}
      style={{
        position: 'absolute',
        left: `${(x * 100).toFixed(2)}%`,
        top: `${(y * 100).toFixed(2)}%`,
        transform: 'translate(-50%, -100%)',
        cursor: placeMode ? (dragging ? 'grabbing' : 'grab') : 'default',
        userSelect: 'none',
      }}
    >
      <svg
        width={24}
        height={32}
        viewBox="0 0 24 32"
        fill={color}
        stroke="rgba(0,0,0,0.4)"
        strokeWidth={1}
      >
        <path d="M12 0C5.4 0 0 5.4 0 12c0 8.4 12 20 12 20s12-11.6 12-20C24 5.4 18.6 0 12 0z" />
      </svg>
      <div
        style={{
          position: 'absolute',
          top: 1,
          left: '50%',
          transform: 'translateX(-50%)',
          fontSize: 9,
          color: '#fff',
          fontWeight: 700,
          textShadow: '0 0 2px rgba(0,0,0,0.7)',
          width: 22,
          textAlign: 'center',
          overflow: 'hidden',
          whiteSpace: 'nowrap',
        }}
      >
        {(placement.hostname || '').slice(0, 3).toUpperCase()}
      </div>
    </div>
  );
}

function EmptyCanvas({ message }: { message: string }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100%',
        color: 'var(--text-muted)',
        gap: '0.5rem',
      }}
    >
      <svg width={64} height={64} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
        <rect x="3" y="3" width="18" height="18" rx="2" />
        <path d="M9 9h6M9 12h6M9 15h4" />
      </svg>
      <p style={{ margin: 0 }}>{message}</p>
    </div>
  );
}

function clamp01(v: number): number {
  return Math.max(0, Math.min(1, v));
}
