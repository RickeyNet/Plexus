import type { SnmpTestOutcome } from './helpers';

/** The result of an SNMP profile test: what the device answered, or why it failed. */
export function SnmpTestResultCard({ outcome }: { outcome: SnmpTestOutcome }) {
  if (!outcome.ok) {
    return (
      <div
        className="card card-sm"
        style={{ borderLeft: '3px solid var(--danger)' }}
      >
        <strong>SNMP Failed</strong>
        <br />
        <span style={{ opacity: 0.8 }}>{outcome.error}</span>
      </div>
    );
  }
  const data = outcome.data;
  return (
    <div
      className="card card-sm"
      style={{ borderLeft: '3px solid var(--success)' }}
    >
      <strong>SNMP OK</strong> - credentials validated
      <table className="data-table table-sm" style={{ marginTop: '0.5rem' }}>
        <tbody>
          <tr>
            <td style={{ opacity: 0.7 }}>Hostname</td>
            <td>{data?.hostname || ''}</td>
          </tr>
          <tr>
            <td style={{ opacity: 0.7 }}>IP</td>
            <td>{data?.ip_address || ''}</td>
          </tr>
          <tr>
            <td style={{ opacity: 0.7 }}>Device Type</td>
            <td>{data?.device_type || ''}</td>
          </tr>
          <tr>
            <td style={{ opacity: 0.7 }}>Protocol</td>
            <td>{data?.discovery?.protocol || ''}</td>
          </tr>
          <tr>
            <td style={{ opacity: 0.7 }}>Vendor</td>
            <td>{data?.discovery?.vendor || 'unknown'}</td>
          </tr>
          <tr>
            <td style={{ opacity: 0.7 }}>OS</td>
            <td>{data?.discovery?.os || 'unknown'}</td>
          </tr>
          <tr>
            <td style={{ opacity: 0.7 }}>sysDescr</td>
            <td style={{ wordBreak: 'break-word' }}>
              {data?.discovery?.sys_descr || ''}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}
