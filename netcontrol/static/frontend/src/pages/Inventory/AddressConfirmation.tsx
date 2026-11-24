import { useIsAdmin } from '@/api/auth';
import { addressAwaitingConfirmation, type InventoryHost, useConfirmHostAddresses } from '@/api/inventory';
import { useDialogs } from '@/components/DialogProvider-context';

/** Why a host shows the marker (the server's `ADDRESS_AWAITING_CONFIRMATION`). */
const AWAITING_CONFIRMATION_TITLE =
  'A non-admin set this address. Plexus sends it no service credential, default credential or shared SNMP ' +
  'secret, and does not poll it, until an admin confirms the address.';

/** The "awaiting admin confirmation" marker of a host whose address is not confirmed. */
export function AwaitingConfirmationBadge({ host }: { host: InventoryHost }) {
  if (!addressAwaitingConfirmation(host)) return null;
  return (
    <span className="badge badge-warning" title={AWAITING_CONFIRMATION_TITLE}>
      Awaiting admin confirmation
    </span>
  );
}

interface ConfirmButtonProps {
  /** The hosts to confirm (with `groupId`: those and every host of the group). */
  hostIds?: number[];
  groupId?: number;
  label?: string;
  /** Called once the addresses are confirmed. */
  onDone?: () => void;
}

/**
 * Admin only: confirm host addresses, after asking. Renders nothing for a
 * non-admin, or when there is nothing to confirm.
 */
export function ConfirmAddressButton({ hostIds = [], groupId, label = 'Confirm address', onDone }: ConfirmButtonProps) {
  const isAdmin = useIsAdmin();
  const { confirm, alert } = useDialogs();
  const mutation = useConfirmHostAddresses();
  if (!isAdmin || (hostIds.length === 0 && groupId === undefined)) return null;

  const onClick = async () => {
    const count = groupId !== undefined ? 'every address awaiting confirmation in this group' : `${hostIds.length} address(es)`;
    const ok = await confirm({
      title: 'Confirm host addresses',
      message: `Confirm ${count}? Plexus then signs in to them with the service credential and shared SNMP secrets.`,
      confirmLabel: 'Confirm addresses',
      confirmVariant: 'primary',
    });
    if (!ok) return;
    mutation.mutate(
      { hostIds, groupId },
      {
        onSuccess: () => onDone?.(),
        onError: (err) => void alert({ message: (err as Error).message, variant: 'error' }),
      },
    );
  };

  return (
    <button
      type="button"
      className="btn btn-sm btn-secondary"
      onClick={() => void onClick()}
      disabled={mutation.isPending}
      title="Confirm that this address is the device's (admin only)"
    >
      {label}
    </button>
  );
}
