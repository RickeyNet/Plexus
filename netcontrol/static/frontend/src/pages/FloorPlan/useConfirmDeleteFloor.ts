import { GeoFloor, useDeleteGeoFloor } from '@/api/floorPlan';

export function useConfirmDeleteFloor() {
  const remove = useDeleteGeoFloor();
  return async (floor: GeoFloor) => {
    if (!confirm(`Delete floor "${floor.name}" and all its device pins?`)) {
      return { confirmed: false as const };
    }
    try {
      await remove.mutateAsync(floor.id);
      return { confirmed: true as const, ok: true as const };
    } catch (e) {
      return {
        confirmed: true as const,
        ok: false as const,
        error: e instanceof Error ? e.message : String(e),
      };
    }
  };
}
