import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { type Webhook, useRedeliverWebhook, useWebhookDeliveries } from '@/api/webhooks';

import type { FormStatus } from './StatusLine';
import { deliveryTone } from './webhookForm';

/** The delivery log of one webhook, newest attempt first, with Redeliver. */
export function WebhookDeliveriesModal({
  webhook,
  onClose,
  onOutcome,
}: {
  webhook: Webhook;
  onClose: () => void;
  onOutcome: (status: FormStatus) => void;
}) {
  const query = useWebhookDeliveries(webhook.id);
  const redeliver = useRedeliverWebhook();
  const pending = usePendingKeys<number>();

  const onRedeliver = (rowId: number, deliveryId: string) =>
    pending.run(rowId, async () => {
      try {
        const res = await redeliver.mutateAsync({ id: webhook.id, deliveryRowId: rowId });
        onOutcome(
          res.ok
            ? { kind: 'success', message: `Delivery ${deliveryId} sent again (HTTP ${res.status_code}).` }
            : { kind: 'error', message: `Redelivery of ${deliveryId} failed: ${res.error || res.status}.` },
        );
      } catch (err) {
        onOutcome({ kind: 'error', message: `Redelivery failed: ${(err as Error).message}` });
      }
    });

  let body;
  if (query.isError && !query.data) body = <QueryError what="deliveries" query={query} />;
  else if (!query.data) body = <LoadingState />;
  else if (query.data.deliveries.length === 0)
    body = <EmptyState compact message="No deliveries yet. Change a subscribed object or send a test." />;
  else
    body = (
      <DataTable compact aria-label={`Deliveries of ${webhook.name}`}>
        <thead>
          <tr>
            <th>Time</th>
            <th>Event</th>
            <th>Object</th>
            <th>Attempt</th>
            <th>Status</th>
            <th>HTTP</th>
            <th>Latency</th>
            <th>Error / response</th>
            <th aria-label="Actions"></th>
          </tr>
        </thead>
        <tbody>
          {query.data.deliveries.map((d) => {
            const detail = d.error || d.response_body;
            return (
              <tr key={d.id}>
                <td>{formatBackendDateTime(d.created_at)}</td>
                <td>
                  <span className="form-mono" title={`Delivery ${d.delivery_id}`}>
                    {d.event}
                  </span>
                </td>
                <td>{d.object_id ? `${d.object_type} ${d.object_id}` : '-'}</td>
                <td>{d.attempt}</td>
                <td>
                  <Badge tone={deliveryTone(d.status)} size="sm">
                    {d.status}
                  </Badge>
                </td>
                <td>{d.status_code ?? '-'}</td>
                <td>{d.latency_ms != null ? `${Math.round(d.latency_ms)} ms` : '-'}</td>
                <td className="text-muted">
                  {detail ? (
                    <span className="form-mono delivery-cell-truncate" title={detail}>
                      {detail}
                    </span>
                  ) : (
                    '-'
                  )}
                </td>
                <td>
                  <BusyButton
                    className="btn btn-xs btn-secondary"
                    busy={pending.isPending(d.id)}
                    busyLabel="Sending…"
                    onClick={() => void onRedeliver(d.id, d.delivery_id)}
                    aria-label={`Redeliver ${d.delivery_id}`}
                  >
                    Redeliver
                  </BusyButton>
                </td>
              </tr>
            );
          })}
        </tbody>
      </DataTable>
    );

  return (
    <Modal isOpen onClose={onClose} title={`Deliveries: ${webhook.name}`} size="large">
      {body}
    </Modal>
  );
}
