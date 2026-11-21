import { describe, expect, it } from 'vitest';

import type { EventReceiverConfig } from '@/api/settings';

import {
  certificateExpiry,
  clientCaBody,
  filterlogSummary,
  generateBody,
  parseSanList,
  pemDownloadHref,
  receiverCounters,
  receiverGuards,
  receiverSettings,
  saveSummary,
  uploadBody,
  validateGenerate,
  validateReceiverPorts,
} from './eventReceivers';

function config(over: Partial<EventReceiverConfig> = {}): EventReceiverConfig {
  return {
    syslog_enabled: true,
    syslog_port: 1514,
    trap_enabled: true,
    trap_port: 10162,
    syslog_alerts: true,
    config_change_trigger: true,
    repoll_trigger: false,
    recollect_trigger: true,
    filterlog_evidence: true,
    syslog_tcp_enabled: false,
    syslog_tcp_port: 1514,
    syslog_tls_enabled: false,
    syslog_tls_port: 6514,
    syslog_tls_require_client_cert: false,
    syslog_udp_actions: true,
    syslog_running: true,
    trap_running: true,
    syslog_received: 1234,
    trap_received: 0,
    syslog_errors: 2,
    trap_errors: 0,
    syslog_last_message_at: '2026-06-15T11:58:00+00:00',
    trap_last_message_at: '',
    events_dropped: 0,
    ...over,
  };
}

describe('receiverSettings', () => {
  it('keeps only the saved settings', () => {
    expect(receiverSettings(config())).toEqual({
      syslog_enabled: true,
      syslog_port: 1514,
      trap_enabled: true,
      trap_port: 10162,
      syslog_alerts: true,
      config_change_trigger: true,
      repoll_trigger: false,
      recollect_trigger: true,
      filterlog_evidence: true,
      syslog_tcp_enabled: false,
      syslog_tcp_port: 1514,
      syslog_tls_enabled: false,
      syslog_tls_port: 6514,
      syslog_tls_require_client_cert: false,
      syslog_udp_actions: true,
    });
  });

  it('drops the stream listener state', () => {
    const body = receiverSettings(config({ syslog_tls_running: true, syslog_tls_error: 'x', syslog_tcp_connections: 3 }));
    expect(Object.keys(body)).not.toContain('syslog_tls_running');
    expect(Object.keys(body)).not.toContain('syslog_tls_error');
    expect(Object.keys(body)).not.toContain('syslog_tcp_connections');
  });
});

describe('validateReceiverPorts', () => {
  it('accepts the defaults', () => {
    expect(validateReceiverPorts(config())).toEqual({});
  });

  it('rejects ports outside 1-65535 and non-integers', () => {
    expect(validateReceiverPorts(config({ syslog_port: 0 })).syslog_port).toBeTruthy();
    expect(validateReceiverPorts(config({ trap_port: 70000 })).trap_port).toBeTruthy();
    expect(validateReceiverPorts(config({ trap_port: 1.5 })).trap_port).toBeTruthy();
  });

  it('rejects the same port for both enabled receivers only', () => {
    expect(validateReceiverPorts(config({ trap_port: 1514 })).trap_port).toContain('different port');
    expect(validateReceiverPorts(config({ trap_port: 1514, trap_enabled: false }))).toEqual({});
  });

  it('checks the TCP and TLS ports, which may share a number with UDP but not with each other', () => {
    expect(validateReceiverPorts(config({ syslog_tls_port: 0 })).syslog_tls_port).toBeTruthy();
    expect(validateReceiverPorts(config({ syslog_tcp_port: 65536 })).syslog_tcp_port).toBeTruthy();
    const both = { syslog_tcp_enabled: true, syslog_tls_enabled: true };
    expect(validateReceiverPorts(config(both))).toEqual({});
    expect(validateReceiverPorts(config({ ...both, syslog_tls_port: 1514 })).syslog_tls_port).toBe(
      'Use a different port from the TCP syslog receiver.',
    );
    expect(validateReceiverPorts(config({ syslog_tcp_enabled: true, syslog_tls_port: 1514 }))).toEqual({});
  });
});

describe('receiverGuards', () => {
  const stored = { has_certificate: true, has_client_ca: true };
  const none = { has_certificate: false, has_client_ca: false };

  it('passes the defaults', () => {
    expect(receiverGuards(config(), config(), none)).toEqual({});
  });

  it('needs a certificate before the TLS receiver is turned on', () => {
    const draft = config({ syslog_tls_enabled: true });
    expect(receiverGuards(draft, config(), none).syslog_tls_enabled).toContain('server certificate');
    expect(receiverGuards(draft, config(), stored)).toEqual({});
    // Already on, or the certificate state not loaded yet: left to the server.
    expect(receiverGuards(draft, draft, none)).toEqual({});
    expect(receiverGuards(draft, config(), undefined)).toEqual({});
  });

  it('needs a client CA before client certificates are required', () => {
    const draft = config({ syslog_tls_require_client_cert: true });
    expect(receiverGuards(draft, config(), { ...stored, has_client_ca: false }).syslog_tls_require_client_cert).toBe(
      'Store a client CA under Client certificates before requiring client certificates.',
    );
    expect(receiverGuards(draft, config(), stored)).toEqual({});
  });

  it('keeps UDP actions on unless TCP or TLS is on', () => {
    const off = config({ syslog_udp_actions: false });
    expect(receiverGuards(off, config(), stored).syslog_udp_actions).toBe(
      'Turn on the syslog TCP or TLS receiver before turning off actions on UDP messages.',
    );
    expect(receiverGuards({ ...off, syslog_tcp_enabled: true }, config(), stored)).toEqual({});
    // Turning TCP off again while UDP actions are off is refused too.
    expect(receiverGuards(off, config({ syslog_udp_actions: false, syslog_tcp_enabled: true }), stored).syslog_udp_actions).toBeTruthy();
  });
});

describe('saveSummary', () => {
  it('names each receiver state', () => {
    const text = saveSummary(config({ trap_running: false, syslog_enabled: true }));
    expect(text).toContain('Syslog over UDP listening on UDP 1514');
    expect(text).toContain('SNMP traps failed to start on UDP 10162');
    expect(saveSummary(config({ syslog_enabled: false, trap_enabled: false }))).toBe(
      'Receiver settings saved: Syslog over UDP off, Syslog over TCP off, Syslog over TLS off, SNMP traps off.',
    );
  });

  it('gives the stream listener port and the reason one did not start', () => {
    const text = saveSummary(
      config({
        syslog_tcp_enabled: true,
        syslog_tcp_running: true,
        syslog_tls_enabled: true,
        syslog_tls_running: false,
        syslog_tls_error: 'No server certificate is stored.',
      }),
    );
    expect(text).toContain('Syslog over TCP listening on TCP 1514');
    expect(text).toContain('Syslog over TLS did not start: No server certificate is stored,');
  });
});

describe('receiverCounters', () => {
  const now = Date.parse('2026-06-15T12:00:00Z');

  it('shows received count, last message age and unreadable count', () => {
    const items = receiverCounters(config(), 'syslog', now);
    expect(items.map((i) => i.label)).toEqual(['Received', 'Last message', 'Unreadable']);
    expect(items[0].value).toBe((1234).toLocaleString());
    expect(items[1].value).toBe('2m ago');
    expect(items[2].tone).toBe('warning');
  });

  it('says none yet before the first message', () => {
    const items = receiverCounters(config(), 'trap', now);
    expect(items[0].value).toBe('0');
    expect(items[1].value).toBe('None yet');
    expect(items[2].tone).toBeUndefined();
  });

  it('adds the connections of a stream listener', () => {
    const items = receiverCounters(
      config({ syslog_tls_received: 40, syslog_tls_errors: 1, syslog_tls_connections: 6, syslog_tls_connections_refused: 2 }),
      'syslog_tls',
      now,
    );
    expect(items.map((i) => i.label)).toEqual(['Received', 'Last message', 'Errors', 'Open connections', 'Connections refused']);
    expect(items.map((i) => i.value)).toEqual(['40', 'None yet', '1', '6', '2']);
    expect(items[2].tone).toBe('warning');
  });
});

describe('certificateExpiry', () => {
  const now = Date.parse('2026-06-15T12:00:00Z');

  it('flags an expired certificate and one that ends within 30 days', () => {
    expect(certificateExpiry('2026-06-01T00:00:00Z', now)).toMatchObject({ state: 'expired' });
    expect(certificateExpiry('2026-06-01T00:00:00Z', now).text).toMatch(/^Expired on /);
    const soon = certificateExpiry('2026-06-27T12:00:00Z', now);
    expect([soon.state, soon.days]).toEqual(['expiring', 12]);
    expect(soon.text).toMatch(/^Expires in 12 days, on /);
    expect(certificateExpiry('2026-06-16T13:00:00Z', now).text).toMatch(/^Expires in 1 day,/);
    expect(certificateExpiry('2026-06-15T18:00:00Z', now).text).toMatch(/^Expires in less than a day,/);
  });

  it('reads a later end date as valid', () => {
    const later = certificateExpiry('2028-09-18T12:00:00Z', now);
    expect(later.state).toBe('valid');
    expect(later.text).toMatch(/^Valid until /);
    expect(certificateExpiry('not a date', now).state).toBe('valid');
  });
});

describe('certificate forms', () => {
  it('splits names on lines, commas and spaces, dropping blanks and repeats', () => {
    expect(parseSanList('plexus.example.com\n192.0.2.10, 2001:db8::5\n\n plexus.example.com ,')).toEqual([
      'plexus.example.com',
      '192.0.2.10',
      '2001:db8::5',
    ]);
    expect(parseSanList('  ')).toEqual([]);
  });

  it('checks the generate bounds and builds its body', () => {
    const form = { commonName: ' plexus.example.com ', sans: 'plexus.example.com\n192.0.2.10', days: 825 };
    expect(validateGenerate(form)).toEqual({});
    expect(generateBody(form)).toEqual({ common_name: 'plexus.example.com', sans: ['plexus.example.com', '192.0.2.10'], days: 825 });
    expect(validateGenerate({ ...form, commonName: ' ' }).commonName).toBeTruthy();
    expect(validateGenerate({ ...form, commonName: 'a'.repeat(65) }).commonName).toBeTruthy();
    expect(validateGenerate({ ...form, days: 0 }).days).toBeTruthy();
    expect(validateGenerate({ ...form, days: 3651 }).days).toBeTruthy();
    expect(validateGenerate({ ...form, days: 1.5 }).days).toBeTruthy();
    const many = Array.from({ length: 33 }, (_, i) => `host${i}.example.com`).join(',');
    expect(validateGenerate({ ...form, sans: many }).sans).toBeTruthy();
  });

  it('sends the certificate and key together', () => {
    expect(uploadBody(' CERT-PLACEHOLDER ', 'KEY-PLACEHOLDER\n')).toEqual({ cert_pem: 'CERT-PLACEHOLDER', key_pem: 'KEY-PLACEHOLDER' });
    expect(uploadBody('', '')).toBe('Paste the certificate and its private key.');
    expect(uploadBody('CERT-PLACEHOLDER', ' ')).toBe('Paste the private key of this certificate.');
    expect(uploadBody('', 'KEY-PLACEHOLDER')).toBe('Paste the certificate that belongs to this private key.');
  });

  it('removes the client CA only while client certificates are not required', () => {
    expect(clientCaBody(' CA-PLACEHOLDER ', true)).toEqual({ client_ca_pem: 'CA-PLACEHOLDER' });
    expect(clientCaBody('', false)).toEqual({ client_ca_pem: '' });
    expect(clientCaBody('  ', true)).toContain('Turn off Require client certificates');
  });

  it('downloads a PEM from a data URL', () => {
    expect(pemDownloadHref('A B\n')).toBe('data:application/x-pem-file;charset=utf-8,A%20B%0A');
  });
});

describe('filterlogSummary', () => {
  it('counts the lines kept and dropped', () => {
    expect(filterlogSummary(config())).toBe('OPNsense firewall log lines since Plexus started: 0 counted, 0 dropped.');
    expect(filterlogSummary(config({ filterlog_received: 1200, filterlog_dropped: 3, filterlog_unknown_source: 2 }))).toBe(
      'OPNsense firewall log lines since Plexus started: 1,200 counted, 3 dropped (2 from addresses that are no inventory host).',
    );
  });
});
