export interface ModalActionsProps {
  onClose: () => void;
  primaryLabel: string;
  primaryDisabled?: boolean;
  onPrimary: () => void;
}

/**
 * The standard two-button modal footer: Cancel, then the primary action.
 * Pass it as a `<Modal>`'s `footer`. A form that submits natively puts its
 * own `type="submit"` button (with `form={id}`) in the footer instead.
 */
export function ModalActions({ onClose, primaryLabel, primaryDisabled, onPrimary }: ModalActionsProps) {
  return (
    <>
      <button type="button" className="btn btn-secondary" onClick={onClose}>
        Cancel
      </button>
      <button type="button" className="btn btn-primary" disabled={primaryDisabled} onClick={onPrimary}>
        {primaryLabel}
      </button>
    </>
  );
}
