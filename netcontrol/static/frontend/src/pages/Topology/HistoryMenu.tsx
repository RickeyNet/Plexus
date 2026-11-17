import { useDeleteToolHistory, useToolHistory, type ToolHistoryEntry, type ToolKind } from '@/api/toolHistory';
import { useDialogs } from '@/components/DialogProvider-context';
import { Menu, MenuItem, MenuSeparator } from '@/components/Menu';
import { formatRelativeTime } from '@/lib/datetime';

/** The words for one tool's runs: "trace" / "traces", "sweep" / "sweeps"... */
export interface HistoryNoun {
  one: string;
  many: string;
}

/**
 * The History button of Path Mode, the Reachability sweep and Summarize:
 * the user's last runs of the tool, newest first; picking one hands its
 * inputs to `onOpen`. Clear history forgets them all, after a confirm.
 */
export function HistoryMenu<T>({
  kind,
  noun,
  label,
  onOpen,
  enabled = true,
}: {
  kind: ToolKind;
  noun: HistoryNoun;
  /** One line naming a run. */
  label: (data: T) => string;
  onOpen: (data: T) => void;
  /** Off: the history is not read (the tool is not shown). */
  enabled?: boolean;
}) {
  const history = useToolHistory<T>(kind, enabled);
  const clear = useDeleteToolHistory(kind);
  const { confirm, alert } = useDialogs();

  async function clearAll() {
    const count = history.data?.entries.length ?? 0;
    const ok = await confirm({
      title: `Clear ${noun.one} history`,
      message: `Forget your ${count} saved ${count === 1 ? noun.one : noun.many}? This cannot be undone.`,
      confirmLabel: 'Clear history',
      confirmVariant: 'danger',
    });
    if (!ok) return;
    try {
      await clear.mutateAsync(null);
    } catch (e) {
      await alert({ title: 'History not cleared', message: (e as Error).message, variant: 'error' });
    }
  }

  const entries: ToolHistoryEntry<T>[] = history.data?.entries ?? [];
  return (
    <Menu
      label={`${noun.one[0].toUpperCase()}${noun.one.slice(1)} history`}
      align="end"
      width={380}
      trigger={(isOpen) => (
        <button type="button" className={`btn btn-sm ${isOpen ? 'btn-primary' : 'btn-secondary'}`} title={`Open one of your last ${noun.many} again`}>
          History ▾
        </button>
      )}
    >
      {history.isPending ? (
        <MenuItem disabled>Loading your {noun.many}…</MenuItem>
      ) : history.error ? (
        <MenuItem disabled>Could not load your {noun.many}: {(history.error as Error).message}</MenuItem>
      ) : !entries.length ? (
        <MenuItem disabled description={`Each ${noun.one} you run is kept here.`}>No {noun.many} yet</MenuItem>
      ) : (
        <>
          {entries.map((entry) => {
            const text = label(entry.data);
            return (
              <MenuItem key={entry.id} onSelect={() => onOpen(entry.data)} description={formatRelativeTime(entry.used_at)} title={text}>
                {text}
              </MenuItem>
            );
          })}
          <MenuSeparator />
          <MenuItem danger onSelect={() => void clearAll()} description={`Plexus keeps your last ${history.data?.limit ?? entries.length} ${noun.many}.`}>
            Clear history
          </MenuItem>
        </>
      )}
    </Menu>
  );
}
