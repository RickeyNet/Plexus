import { type ReactNode, useMemo, useState } from 'react';

import { LoadingState } from '@/components/LoadingState';
import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  FloorPlacement,
  GeoFloor,
  GeoSiteSummary,
  InventoryHost,
  useFloorPlacements,
  useGeoFloor,
  useGeoOverview,
  useGeoSite,
  useGeoSites,
  useInventoryGroupsWithHosts,
} from '@/api/floorPlan';
import { clickableProps } from '@/lib/clickable';

import { FloorCanvas } from './FloorCanvas';
import {
  AddFloorModal,
  AddSiteModal,
  EditFloorModal,
  UploadImageModal,
} from './modals';
import { statusColor } from './statusColor';
import { useConfirmDeleteFloor } from './useConfirmDeleteFloor';

type ModalKind = 'add-site' | 'add-floor' | 'edit-floor' | 'upload-image' | null;

export function FloorPlan() {
  const { alert } = useDialogs();
  const sites = useGeoOverview();
  // Host counts per site come with the site list (GET /geo/sites).
  const siteRows = useGeoSites();
  const hostCounts = useMemo(
    () => new Map((siteRows.data ?? []).map((s) => [s.id, s.host_count])),
    [siteRows.data],
  );
  const [siteId, setSiteId] = useState<number | null>(null);
  const [floorId, setFloorId] = useState<number | null>(null);
  const [placeMode, setPlaceMode] = useState(false);
  const [modal, setModal] = useState<ModalKind>(null);

  const site = useGeoSite(siteId);
  const floor = useGeoFloor(floorId);
  const placements = useFloorPlacements(floorId);

  // Only fetch inventory groups when the user enters place-mode, matching the
  // legacy module's lazy load.
  const inventory = useInventoryGroupsWithHosts(placeMode);

  const allHosts: InventoryHost[] = useMemo(
    () => (inventory.data ?? []).flatMap((g) => g.hosts ?? []),
    [inventory.data],
  );

  const placedIds = useMemo(
    () => new Set((placements.data ?? []).map((p) => p.host_id)),
    [placements.data],
  );

  const unplaced = useMemo(
    () => allHosts.filter((h) => !placedIds.has(h.id)),
    [allHosts, placedIds],
  );

  const confirmDeleteFloor = useConfirmDeleteFloor();

  const sitesError = sites.isError && !sites.data && (
    <QueryError what="sites" query={sites} />
  );
  const floorsError = site.isError && !site.data && (
    <QueryError what="floors" query={site} />
  );
  const floorError = floor.isError && !floor.data && (
    <QueryError what="floor" query={floor} />
  );
  const placementsError = placements.isError && !placements.data && (
    <QueryError what="device placements" query={placements} />
  );
  const inventoryError = inventory.isError && !inventory.data && (
    <QueryError what="inventory devices" query={inventory} />
  );

  return (
    <>
      <PageHeader title="Floor Plan Mapping">
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => setModal('add-site')}
        >
          + Add Site
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => sites.refetch()}
          disabled={sites.isFetching}
        >
          Refresh
        </button>
      </PageHeader>

      <PageHelp
        pageKey="floor-plan"
        title="Place Devices on Floor Plans"
        text="Upload floor plan images per site, then drag inventory devices onto them. Devices show live status colors so you can locate problems geographically - handy for closet-based switch ops and physical site reviews."
      />

      <div
        style={{
          display: 'flex',
          gap: '1rem',
          height: 'calc(100vh - 220px)',
          overflow: 'hidden',
        }}
      >
        <SitesPanel
          sites={sites.data}
          hostCounts={hostCounts}
          loading={sites.isPending}
          loadError={sitesError}
          activeSiteId={siteId}
          activeFloorId={floorId}
          siteFloors={site.data?.floors}
          floorsError={floorsError}
          onSelectSite={(id) => {
            setSiteId(id);
            setFloorId(null);
            setPlaceMode(false);
          }}
          onSelectFloor={(id) => {
            setFloorId(id);
            setPlaceMode(false);
          }}
        />

        <CanvasPanel
          site={site.data ?? null}
          floor={floor.data ?? null}
          floorError={floorError || placementsError}
          placements={placements.data ?? []}
          placementsLoading={floor.data !== null && placements.isPending}
          placeMode={placeMode}
          onTogglePlaceMode={() => setPlaceMode((v) => !v)}
          onAddFloor={() => setModal('add-floor')}
          onUploadImage={() => setModal('upload-image')}
          onEditFloor={() => setModal('edit-floor')}
          onDeleteFloor={async () => {
            if (!floor.data) return;
            const result = await confirmDeleteFloor(floor.data);
            if (result.confirmed && result.ok) {
              setFloorId(null);
            } else if (result.confirmed && !result.ok) {
              void alert({
                message: `Failed to delete floor: ${result.error}`,
                variant: 'error',
              });
            }
          }}
          unplaced={unplaced}
          unplacedError={inventoryError}
        />
      </div>

      {modal === 'add-site' && <AddSiteModal onClose={() => setModal(null)} />}
      {modal === 'add-floor' && siteId !== null && (
        <AddFloorModal siteId={siteId} onClose={() => setModal(null)} />
      )}
      {modal === 'edit-floor' && floor.data && (
        <EditFloorModal floor={floor.data} onClose={() => setModal(null)} />
      )}
      {modal === 'upload-image' && floorId !== null && (
        <UploadImageModal floorId={floorId} onClose={() => setModal(null)} />
      )}
    </>
  );
}

// ── Left panel: site + floor list ──────────────────────────────────────────

function SitesPanel({
  sites,
  hostCounts,
  loading,
  loadError,
  activeSiteId,
  activeFloorId,
  siteFloors,
  floorsError,
  onSelectSite,
  onSelectFloor,
}: {
  sites: GeoSiteSummary[] | undefined;
  /** Hosts linked to each site, by site id, when the server reports it. */
  hostCounts: Map<number, number | null | undefined>;
  loading: boolean;
  loadError: ReactNode;
  activeSiteId: number | null;
  activeFloorId: number | null;
  siteFloors: GeoFloor[] | undefined;
  floorsError: ReactNode;
  onSelectSite: (id: number) => void;
  onSelectFloor: (id: number) => void;
}) {
  return (
    <div
      style={{
        width: 240,
        minWidth: 180,
        flexShrink: 0,
        overflowY: 'auto',
        background: 'var(--card-bg)',
        border: '1px solid var(--border)',
        borderRadius: '0.5rem',
        padding: '0.5rem',
      }}
    >
      {loadError}
      {loading && <LoadingState text="Loading sites…" />}
      {sites && sites.length === 0 && (
        <div style={{ padding: '0.75rem', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
          No sites yet.
          <br />
          Click <strong>+ Add Site</strong> to create one.
        </div>
      )}
      {sites?.map((s) => {
        const isActive = activeSiteId === s.id;
        const online = Number(s.online_count) || 0;
        const offline = Number(s.offline_count) || 0;
        const unknown = Number(s.unknown_count) || 0;
        const placed = Number(s.placed_device_count) || 0;
        const floors = Number(s.floor_count) || 0;
        const hosts = s.host_count ?? hostCounts.get(s.id);
        return (
          <div
            key={s.id}
            style={{
              padding: '0.5rem 0.6rem',
              borderRadius: 4,
              cursor: 'pointer',
              marginBottom: 2,
              background: isActive ? 'var(--primary-soft)' : undefined,
            }}
          >
            <div
              {...clickableProps(() => onSelectSite(s.id))}
              aria-current={isActive ? 'true' : undefined}
            >
              <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{s.name}</div>
              {s.address && (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {s.address}
                </div>
              )}
              <div
                style={{
                  fontSize: '0.72rem',
                  color: 'var(--text-muted)',
                  marginTop: 2,
                }}
              >
                {floors} floor{floors !== 1 ? 's' : ''} · {placed} pinned
                {typeof hosts === 'number' && ` · ${hosts} host${hosts !== 1 ? 's' : ''}`}
                {online > 0 && (
                  <span style={{ color: 'var(--success)', marginLeft: 4 }}>● {online}</span>
                )}
                {offline > 0 && (
                  <span style={{ color: 'var(--danger)', marginLeft: 4 }}>● {offline}</span>
                )}
                {unknown > 0 && (
                  <span style={{ color: 'var(--text-muted)', marginLeft: 4 }}>● {unknown}</span>
                )}
              </div>
            </div>
            {isActive && (
              <FloorList
                floors={siteFloors}
                loadError={floorsError}
                activeFloorId={activeFloorId}
                onSelect={onSelectFloor}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

function FloorList({
  floors,
  loadError,
  activeFloorId,
  onSelect,
}: {
  floors: GeoFloor[] | undefined;
  loadError: ReactNode;
  activeFloorId: number | null;
  onSelect: (id: number) => void;
}) {
  return (
    <div
      style={{ display: 'block', marginTop: '0.4rem', paddingLeft: '0.6rem' }}
      onClick={(e) => e.stopPropagation()}
    >
      {loadError}
      {floors && floors.length === 0 && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          No floors - add one above
        </div>
      )}
      {floors?.map((f) => {
        const isActive = activeFloorId === f.id;
        return (
          <div
            key={f.id}
            {...clickableProps(() => onSelect(f.id))}
            aria-current={isActive ? 'true' : undefined}
            style={{
              padding: '3px 6px',
              borderRadius: 3,
              cursor: 'pointer',
              fontSize: '0.81rem',
              background: isActive ? 'var(--primary-soft)' : undefined,
              fontWeight: isActive ? 600 : undefined,
            }}
          >
            {f.name}
            {f.placed_device_count ? (
              <span style={{ color: 'var(--text-muted)' }}>
                {' '}
                ({f.placed_device_count})
              </span>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

// ── Right panel: canvas + toolbar ──────────────────────────────────────────

function CanvasPanel({
  site,
  floor,
  floorError,
  placements,
  placementsLoading,
  placeMode,
  onTogglePlaceMode,
  onAddFloor,
  onUploadImage,
  onEditFloor,
  onDeleteFloor,
  unplaced,
  unplacedError,
}: {
  site: { name: string } | null;
  floor: GeoFloor | null;
  floorError: ReactNode;
  placements: FloorPlacement[];
  placementsLoading: boolean;
  placeMode: boolean;
  onTogglePlaceMode: () => void;
  onAddFloor: () => void;
  onUploadImage: () => void;
  onEditFloor: () => void;
  onDeleteFloor: () => void;
  unplaced: InventoryHost[];
  unplacedError: ReactNode;
}) {
  const breadcrumb = floor
    ? `${site?.name ?? '-'} › ${floor.name}`
    : site
      ? site.name
      : 'Select a site and floor';

  return (
    <div
      style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: 'var(--card-bg)',
        border: '1px solid var(--border)',
        borderRadius: '0.5rem',
      }}
    >
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          alignItems: 'center',
          padding: '0.5rem 0.75rem',
          borderBottom: '1px solid var(--border)',
          flexWrap: 'wrap',
        }}
      >
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {breadcrumb}
        </span>
        <span style={{ flex: 1 }} />
        {site && (
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={onAddFloor}
          >
            + Add Floor
          </button>
        )}
        {floor && (
          <>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={onUploadImage}
            >
              Upload Floor Plan
            </button>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={onEditFloor}
            >
              Edit Floor
            </button>
            <button
              type="button"
              className="btn btn-sm btn-danger"
              onClick={onDeleteFloor}
            >
              Delete Floor
            </button>
            <label
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem' }}
            >
              <input
                type="checkbox"
                checked={placeMode}
                onChange={onTogglePlaceMode}
              />
              Edit pins
            </label>
          </>
        )}
      </div>

      <div
        style={{
          flex: 1,
          overflow: 'auto',
          position: 'relative',
          background: 'var(--bg)',
          padding: floor?.image_filename ? 0 : '1rem',
        }}
      >
        {floorError}
        {!floor && !floorError && (
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
            <svg
              width={64}
              height={64}
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.5}
            >
              <rect x="3" y="3" width="18" height="18" rx="2" />
              <path d="M9 9h6M9 12h6M9 15h4" />
            </svg>
            <p style={{ margin: 0 }}>Select a floor to view its map.</p>
          </div>
        )}
        {floor && placementsLoading && (
          <LoadingState text="Loading floor…" />
        )}
        {floor && !placementsLoading && !floorError && (
          <FloorCanvas
            floor={floor}
            placements={placements}
            placeMode={placeMode}
          />
        )}
      </div>

      {placeMode && floor && (
        <UnplacedDevicesSidebar hosts={unplaced} loadError={unplacedError} />
      )}
    </div>
  );
}

// ── Bottom: unplaced devices sidebar (drag source) ─────────────────────────

function UnplacedDevicesSidebar({
  hosts,
  loadError,
}: {
  hosts: InventoryHost[];
  loadError: ReactNode;
}) {
  return (
    <div
      style={{
        borderTop: '1px solid var(--border)',
        maxHeight: 200,
        overflowY: 'auto',
        padding: '0.5rem 0.75rem',
      }}
    >
      <div
        style={{
          fontSize: '0.8rem',
          fontWeight: 600,
          marginBottom: '0.4rem',
          color: 'var(--text-muted)',
        }}
      >
        UNPLACED DEVICES - drag onto the floor plan above
      </div>
      {loadError ? (
        loadError
      ) : hosts.length === 0 ? (
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          All devices placed.
        </span>
      ) : (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
          {hosts.map((h) => (
            <div
              key={h.id}
              draggable
              onDragStart={(e) => {
                e.dataTransfer.setData('text/plain', String(h.id));
                e.dataTransfer.effectAllowed = 'copy';
              }}
              style={{
                padding: '3px 8px',
                background: 'var(--card-bg)',
                border: '1px solid var(--border)',
                borderRadius: 12,
                fontSize: '0.78rem',
                cursor: 'grab',
                userSelect: 'none',
              }}
            >
              <span
                style={{
                  display: 'inline-block',
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: statusColor(h.status),
                  marginRight: 4,
                }}
              />
              {h.hostname}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
