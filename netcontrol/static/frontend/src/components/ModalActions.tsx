import { BusyButton } from './BusyButton';

export interface ModalActionsProps {
  onClose: () => void;
  primaryLabel: string;
  primaryDisabled?: boolean;
  /** The primary action is in flight: spinner, disabled, `aria-busy`. */
  primaryBusy?: boolean;
  /** Replaces the primary label while busy ("Saving…"). */
  primaryBusyLabel?: string;
  onPrimary: () => void;
}

/**
 * The standard two-button modal footer: Cancel, then the primary action.
 * Pass it as a `<Modal>`'s `footer`. A form that submits natively puts its
 * own `type="submit"` button (with `form={id}`) in the footer instead.
 */
export function ModalActions({
  onClose,
  primaryLabel,
  primaryDisabled,
  primaryBusy = false,
  primaryBusyLabel,
  onPrimary,
}: ModalActionsProps) {
  return (
    <>
      <button type="button" className="btn btn-secondary" onClick={onClose}>
        Cancel
      </button>
      <BusyButton
        className="btn btn-primary"
        busy={primaryBusy}
        busyLabel={primaryBusyLabel}
        disabled={primaryDisabled}
        onClick={onPrimary}
      >
        {primaryLabel}
      </BusyButton>
    </>
  );
}
