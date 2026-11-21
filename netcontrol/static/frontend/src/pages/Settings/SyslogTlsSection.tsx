import { type FormEvent, useState } from 'react';
import type { UseQueryResult } from '@tanstack/react-query';

import {
  type SyslogTlsCertificate,
  type SyslogTlsState,
  useDeleteSyslogTls,
  useGenerateSyslogTls,
  useSaveSyslogTls,
} from '@/api/settings';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { CopyButton } from '@/components/CopyButton';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { SegmentedControl } from '@/components/SegmentedControl';
import { formatBackendDate } from '@/lib/datetime';

import {
  certificateExpiry,
  clientCaBody,
  DEFAULT_CERT_DAYS,
  type GenerateErrors,
  type GenerateForm,
  generateBody,
  MAX_SANS,
  pemDownloadHref,
  uploadBody,
  validateGenerate,
} from './eventReceivers';
import { FormRow, NumberField, PemField, TextField } from './FormFields';
import { SaveBar } from './SaveBar';
import { type FormStatus, StatusLine } from './StatusLine';
import { useSavedDraft } from './useSavedDraft';

type CertSource = 'generate' | 'upload';

const SOURCE_OPTIONS: { key: CertSource; label: string }[] = [
  { key: 'generate', label: 'Generate self-signed' },
  { key: 'upload', label: 'Upload from your CA' },
];

const SECTION_STYLE = { marginTop: '1.5rem' } as const;

/** Expired or expiring soon as a badge; null while comfortably valid. */
function ExpiryBadge({ notAfter }: { notAfter: string }) {
  const expiry = certificateExpiry(notAfter);
  if (expiry.state === 'valid') return null;
  return (
    <Badge tone={expiry.state === 'expired' ? 'danger' : 'warning'} size="sm">
      {expiry.state === 'expired' ? 'Expired' : 'Expires soon'}
    </Badge>
  );
}

function errorMessage(err: unknown): string {
  return (err as Error).message;
}

/**
 * Settings > Syslog & Traps: the server certificate of the syslog TLS
 * receiver (generate, upload, remove) and the client CA of mutual TLS. Each
 * action saves on its own, apart from the receiver settings form above.
 * `tlsEnabled` and `requireClientCert` are the saved receiver settings.
 */
export function SyslogTlsSection({ query, tlsEnabled, requireClientCert }: {
  query: UseQueryResult<SyslogTlsState, Error>;
  tlsEnabled: boolean;
  requireClientCert: boolean;
}) {
  const data = query.data;
  return (
    <>
      <section style={SECTION_STYLE} aria-labelledby="syslog-tls-cert-heading">
        <h4 id="syslog-tls-cert-heading" style={{ margin: '0 0 0.5rem 0' }}>TLS certificate</h4>
        <p className="form-help" style={{ marginTop: 0 }}>
          The syslog TLS receiver presents this certificate to devices. Saving, generating or removing the certificate
          or the client CA restarts the TLS receiver, which drops its open connections.
        </p>
        {!data ? (
          query.isError ? <QueryError what="TLS certificate" query={query} /> : <LoadingState />
        ) : (
          <ServerCertificate tls={data} tlsEnabled={tlsEnabled} />
        )}
      </section>
      {data && (
        <section style={SECTION_STYLE} aria-labelledby="syslog-tls-ca-heading">
          <h4 id="syslog-tls-ca-heading" style={{ margin: '0 0 0.5rem 0' }}>Client certificates (mutual TLS)</h4>
          <ClientCa tls={data} requireClientCert={requireClientCert} />
        </section>
      )}
    </>
  );
}

function ServerCertificate({ tls, tlsEnabled }: { tls: SyslogTlsState; tlsEnabled: boolean }) {
  const { confirm } = useDialogs();
  const remove = useDeleteSyslogTls();
  const [status, setStatus] = useState<FormStatus | null>(null);
  const [source, setSource] = useState<CertSource>('generate');
  const cert = tls.has_certificate ? tls.certificate : null;

  const onRemove = async () => {
    if (tlsEnabled) {
      setStatus({
        kind: 'error',
        message: 'Turn off the syslog TLS receiver and save the receiver settings before removing its certificate.',
      });
      return;
    }
    const agreed = await confirm({
      title: 'Remove TLS certificate',
      message: 'Remove the server certificate and its private key? The TLS receiver cannot start until you store or generate another. The client CA is kept.',
      confirmLabel: 'Remove certificate',
    });
    if (!agreed) return;
    setStatus(null);
    remove.mutate(undefined, {
      onSuccess: () => setStatus({ kind: 'success', message: 'Certificate removed.' }),
      onError: (err) => setStatus({ kind: 'error', message: `Could not remove the certificate: ${errorMessage(err)}` }),
    });
  };

  return (
    <>
      {cert ? (
        <>
          <CertificateDetails cert={cert} />
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', margin: '0.5rem 0 1rem 0' }}>
            <CopyButton text={tls.cert_pem} label="Copy certificate" />
            <a className="btn btn-sm btn-secondary" href={pemDownloadHref(tls.cert_pem)} download="plexus-syslog-server.pem">
              Download certificate
            </a>
            <BusyButton
              className="btn btn-sm btn-danger"
              busy={remove.isPending}
              busyLabel="Removing…"
              onClick={() => void onRemove()}
            >
              Remove certificate
            </BusyButton>
          </div>
          <p className="form-help" style={{ marginTop: 0 }}>
            Devices that do not trust your CA must be given this certificate to trust Plexus (on Cisco, as a trustpoint).
          </p>
        </>
      ) : (
        <p className="text-muted" style={{ marginTop: 0 }}>
          No server certificate is stored, so the TLS receiver cannot start. Generate a self-signed certificate or
          upload one from your CA.
        </p>
      )}

      <h5 style={{ margin: '1rem 0 0.5rem 0' }}>{cert ? 'Replace the certificate' : 'Store a certificate'}</h5>
      <SegmentedControl aria-label="Certificate source" options={SOURCE_OPTIONS} value={source} onChange={setSource} />
      <div style={{ marginTop: '0.75rem' }}>
        {source === 'generate' ? (
          <GenerateCertificate tls={tls} onStatus={setStatus} />
        ) : (
          <UploadCertificate replaces={cert !== null} onStatus={setStatus} />
        )}
      </div>
      <div aria-live="polite">
        <StatusLine status={status} />
      </div>
    </>
  );
}

function CertificateDetails({ cert }: { cert: SyslogTlsCertificate }) {
  const expiry = certificateExpiry(cert.not_after);
  return (
    <DataTable compact aria-label="Stored server certificate">
      <tbody>
        <tr>
          <th scope="row">Subject</th>
          <td style={{ overflowWrap: 'anywhere' }}>
            {cert.subject}{' '}
            {cert.self_signed && <Badge size="sm">Self-signed</Badge>}
          </td>
        </tr>
        <tr>
          <th scope="row">Issuer</th>
          <td style={{ overflowWrap: 'anywhere' }}>{cert.issuer}</td>
        </tr>
        <tr>
          <th scope="row">Valid from</th>
          <td>{formatBackendDate(cert.not_before)}</td>
        </tr>
        <tr>
          <th scope="row">Valid until</th>
          <td>
            {expiry.text} <ExpiryBadge notAfter={cert.not_after} />
          </td>
        </tr>
        <tr>
          <th scope="row">SHA-256 fingerprint</th>
          <td>
            <code style={{ overflowWrap: 'anywhere' }}>{cert.sha256_fingerprint}</code>
          </td>
        </tr>
        <tr>
          <th scope="row">Names and addresses</th>
          <td style={{ overflowWrap: 'anywhere' }}>{cert.sans.length ? cert.sans.join(', ') : 'None'}</td>
        </tr>
      </tbody>
    </DataTable>
  );
}

function initialGenerateForm(tls: SyslogTlsState): GenerateForm {
  const cert = tls.has_certificate ? tls.certificate : null;
  // The name the browser reached Plexus by is a likely name for devices too.
  const host = typeof window === 'undefined' ? '' : window.location.hostname;
  return {
    commonName: host,
    sans: cert?.sans.length ? cert.sans.join('\n') : host,
    days: DEFAULT_CERT_DAYS,
  };
}

function GenerateCertificate({ tls, onStatus }: { tls: SyslogTlsState; onStatus: (s: FormStatus | null) => void }) {
  const generate = useGenerateSyslogTls();
  const [form, setForm] = useState<GenerateForm>(() => initialGenerateForm(tls));
  const [errors, setErrors] = useState<GenerateErrors>({});

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const found = validateGenerate(form);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    onStatus(null);
    generate.mutate(generateBody(form), {
      onSuccess: () => onStatus({ kind: 'success', message: 'Self-signed certificate generated and stored.' }),
      onError: (err) => onStatus({ kind: 'error', message: `Could not generate the certificate: ${errorMessage(err)}` }),
    });
  };

  const set = (next: Partial<GenerateForm>) => {
    setForm({ ...form, ...next });
    // An edited field's error clears at once; the rest wait for the next try.
    const cleared = { ...errors };
    for (const key of Object.keys(next) as (keyof GenerateForm)[]) delete cleared[key];
    setErrors(cleared);
  };

  return (
    <form onSubmit={onSubmit} noValidate>
      {tls.has_certificate && (
        <Callout tone="warning" role="note">
          Generating replaces the stored certificate and private key. Devices that trusted the old certificate must be
          given the new one.
        </Callout>
      )}
      <FormRow>
        <TextField
          label="Common name"
          flex="1 1 240px"
          value={form.commonName}
          placeholder="plexus.example.com"
          help={errors.commonName ? <FieldError>{errors.commonName}</FieldError> : 'The name devices use to reach Plexus.'}
          onChange={(v) => set({ commonName: v })}
        />
        <NumberField
          label="Valid for (days)"
          flex="0 1 160px"
          min={1}
          max={3650}
          value={form.days}
          help={errors.days ? <FieldError>{errors.days}</FieldError> : `Default ${DEFAULT_CERT_DAYS}`}
          onChange={(v) => set({ days: v })}
        />
      </FormRow>
      <SanField value={form.sans} error={errors.sans} onChange={(v) => set({ sans: v })} />
      <BusyButton type="submit" className="btn btn-sm btn-primary" busy={generate.isPending} busyLabel="Generating…">
        Generate certificate
      </BusyButton>
    </form>
  );
}

function SanField({ value, error, onChange }: { value: string; error?: string; onChange: (v: string) => void }) {
  return (
    <div className="form-group">
      <label className="form-label" htmlFor="syslog-tls-sans">Names and addresses</label>
      <textarea
        id="syslog-tls-sans"
        className="form-textarea"
        rows={3}
        spellCheck={false}
        autoComplete="off"
        value={value}
        placeholder={'plexus.example.com\n192.0.2.10'}
        aria-describedby="syslog-tls-sans-help"
        onChange={(e) => onChange(e.target.value)}
      />
      <div className="form-help" id="syslog-tls-sans-help">
        {error ? (
          <FieldError>{error}</FieldError>
        ) : (
          `The DNS names and IP addresses devices connect to, one per line or comma separated (up to ${MAX_SANS}).`
        )}
      </div>
    </div>
  );
}

function UploadCertificate({ replaces, onStatus }: { replaces: boolean; onStatus: (s: FormStatus | null) => void }) {
  const save = useSaveSyslogTls();
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [error, setError] = useState('');

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const body = uploadBody(certPem, keyPem);
    if (typeof body === 'string') {
      setError(body);
      return;
    }
    setError('');
    onStatus(null);
    save.mutate(body, {
      onSuccess: () => {
        // The key is write-only: never kept in the form after it is stored.
        setCertPem('');
        setKeyPem('');
        onStatus({ kind: 'success', message: 'Certificate and private key saved.' });
      },
      onError: (err) => onStatus({ kind: 'error', message: `Could not save the certificate: ${errorMessage(err)}` }),
    });
  };

  return (
    <form onSubmit={onSubmit} noValidate>
      {replaces && (
        <Callout tone="warning" role="note">
          Saving replaces the stored certificate and private key.
        </Callout>
      )}
      <FormRow>
        <PemField
          label="Certificate (PEM)"
          value={certPem}
          placeholder={'-----BEGIN CERTIFICATE-----\n…'}
          help="The server certificate first, then any intermediate certificates."
          onChange={(v) => {
            setCertPem(v);
            setError('');
          }}
        />
        <PemField
          label="Private key (PEM)"
          value={keyPem}
          placeholder={'-----BEGIN PRIVATE KEY-----\n…'}
          help="Not encrypted. It is stored encrypted and never shown again."
          onChange={(v) => {
            setKeyPem(v);
            setError('');
          }}
        />
      </FormRow>
      <FieldError>{error}</FieldError>
      <BusyButton type="submit" className="btn btn-sm btn-primary" busy={save.isPending} busyLabel="Saving…">
        Save certificate
      </BusyButton>
    </form>
  );
}

function ClientCa({ tls, requireClientCert }: { tls: SyslogTlsState; requireClientCert: boolean }) {
  const { confirm } = useDialogs();
  const save = useSaveSyslogTls();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft<string>(tls.client_ca_pem);
  const [status, setStatus] = useState<FormStatus | null>(null);
  const text = draft ?? '';

  const store = async (pem: string) => {
    const body = clientCaBody(pem, requireClientCert);
    if (typeof body === 'string') {
      setStatus({ kind: 'error', message: body });
      return;
    }
    const removing = body.client_ca_pem === '';
    if (
      removing
      && !(await confirm({
        title: 'Remove client CA',
        message: 'Remove the client CA? Require client certificates cannot be turned on again until you store one.',
        confirmLabel: 'Remove client CA',
      }))
    ) {
      return;
    }
    setStatus(null);
    save.mutate(body, {
      onSuccess: (saved) => {
        markSaved(saved.client_ca_pem);
        setStatus({ kind: 'success', message: removing ? 'Client CA removed.' : 'Client CA saved.' });
      },
      onError: (err) => setStatus({ kind: 'error', message: `Could not save the client CA: ${errorMessage(err)}` }),
    });
  };

  return (
    <>
      <p className="form-help" style={{ marginTop: 0 }}>
        The CA certificates that sign your devices&apos; client certificates. With Require client certificates on (under
        Syslog over TLS above), only a device holding a certificate one of them signed can connect.
      </p>
      {tls.has_client_ca && tls.client_ca.length > 0 && (
        <DataTable compact aria-label="Stored client CA certificates">
          <thead>
            <tr>
              <th>Subject</th>
              <th>Expires</th>
            </tr>
          </thead>
          <tbody>
            {tls.client_ca.map((ca, i) => (
              <tr key={`${ca.subject}|${i}`}>
                <td style={{ overflowWrap: 'anywhere' }}>{ca.subject}</td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  {formatBackendDate(ca.not_after)} <ExpiryBadge notAfter={ca.not_after} />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
      <PemField
        label="Client CA (PEM)"
        value={text}
        placeholder={'-----BEGIN CERTIFICATE-----\n…'}
        help="One or more CA certificates, up to 100. Leave empty and save to remove the client CA."
        onChange={(v) => {
          setDraft(v);
          setStatus(null);
        }}
      />
      <SaveBar
        name="Client CA"
        dirty={dirty}
        busy={save.isPending}
        label="Save client CA"
        status={status}
        onDiscard={discard}
        onSave={() => void store(text)}
      >
        {tls.has_client_ca && (
          <button type="button" className="btn btn-ghost" disabled={save.isPending} onClick={() => void store('')}>
            Remove client CA
          </button>
        )}
      </SaveBar>
    </>
  );
}
