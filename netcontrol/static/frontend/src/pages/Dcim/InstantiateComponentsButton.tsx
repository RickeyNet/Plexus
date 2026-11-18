import { useInstantiateComponents } from '@/api/dcim';
import { BusyButton } from '@/components/BusyButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { instantiateSummary } from '@/lib/componentTemplates';

/**
 * Creates the components (console, power, front and rear ports, module
 * bays) the device's device type lists and the device lacks, then says what
 * was created and which templated interfaces the device has not reported.
 */
export function InstantiateComponentsButton({ hostId }: { hostId: number }) {
  const run = useInstantiateComponents();
  const { alert } = useDialogs();
  const handle = async () => {
    try {
      const result = await run.mutateAsync(hostId);
      await alert({ title: 'Components from the device type', message: instantiateSummary(result) });
    } catch (err) {
      await alert({ message: `The components were not created: ${(err as Error).message} Try again.`, variant: 'error' });
    }
  };
  return (
    <BusyButton
      className="btn btn-sm btn-secondary"
      busy={run.isPending}
      busyLabel="Creating…"
      title="Create the ports and module bays the device type lists that this device does not have yet"
      onClick={() => void handle()}
    >
      Create components from device type
    </BusyButton>
  );
}
