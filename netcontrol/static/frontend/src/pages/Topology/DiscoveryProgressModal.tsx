import { useEffect, useRef, useState } from 'react';

import { discoverTopologyStream, type DiscoveryStreamEvent } from '@/api/topology';
import { Modal } from '@/components/Modal';

interface Props {
  isOpen: boolean;
  groupId: number | string | null;
  onClose: () => void;
  onComplete: () => void;
}

interface FeedEntry {
  text: string;
  color?: string;
}

export function DiscoveryProgressModal({ isOpen, groupId, onClose, onComplete }: Props) {
  const [title, setTitle] = useState('Initializing discovery...');
  const [subtitle, setSubtitle] = useState('Preparing to scan hosts via SNMP');
  const [step, setStep] = useState('Waiting for stream...');
  const [scanned, setScanned] = useState(0);
  const [total, setTotal] = useState<number | null>(null);
  const [links, setLinks] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [feed, setFeed] = useState<FeedEntry[]>([]);
  const [running, setRunning] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const startedRef = useRef(false);

  function append(entry: FeedEntry) {
    setFeed((f) => [...f, entry]);
  }

  useEffect(() => {
    if (!isOpen) {
      startedRef.current = false;
      return;
    }
    if (startedRef.current) return;
    startedRef.current = true;

    setTitle('Initializing discovery...');
    setSubtitle('Preparing to scan hosts via SNMP');
    setStep('Waiting for stream...');
    setScanned(0); setTotal(null); setLinks(0); setElapsed(0); setFeed([]);
    setRunning(true);

    const controller = new AbortController();
    abortRef.current = controller;
    const startTime = Date.now();
    const elapsedTimer = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);

    let runningLinks = 0;
    let finalResult: DiscoveryStreamEvent | null = null;

    discoverTopologyStream(groupId, (event) => {
      if (event.type === 'start') {
        setTotal(event.total_hosts ?? null);
        setTitle(`Discovering neighbors across ${event.total_groups ?? 0} group(s)...`);
        setSubtitle(`${event.total_hosts ?? 0} host(s) to scan`);
        append({ text: `Starting discovery: ${event.total_hosts} hosts in ${event.total_groups} group(s)`, color: 'var(--text-muted)' });
      } else if (event.type === 'group_start') {
        setStep(`Scanning group: ${event.group}`);
        append({ text: `▶ Group "${event.group}" - ${event.host_count} host(s)`, color: 'var(--primary-light)' });
      } else if (event.type === 'host_walked') {
        setScanned(event.scanned ?? 0);
        runningLinks += event.neighbors ?? 0;
        setLinks(runningLinks);
        setStep(`Walked ${event.hostname}`);
        if (event.ok) {
          const color = (event.neighbors ?? 0) > 0 ? 'var(--success, #22c55e)' : 'var(--text-muted)';
          const icon = (event.neighbors ?? 0) > 0 ? '✓' : '–';
          append({ text: `  ${icon} ${event.hostname} (${event.ip}) - ${event.neighbors} neighbor(s)`, color });
        } else {
          append({ text: `  ✗ ${event.hostname} (${event.ip}) - failed`, color: 'var(--danger, #ef4444)' });
        }
      } else if (event.type === 'db_write_start') {
        setStep(`Saving results for ${event.group}...`);
        append({ text: `  Saving topology data for "${event.group}"...`, color: 'var(--text-muted)' });
      } else if (event.type === 'group_done') {
        append({ text: `✔ Group "${event.group}" complete - ${event.links} link(s)`, color: 'var(--success, #22c55e)' });
      } else if (event.type === 'resolving') {
        setStep('Resolving neighbor identities...');
        append({ text: 'Resolving neighbor host IDs against inventory...', color: 'var(--text-muted)' });
      } else if (event.type === 'done') {
        finalResult = event;
      } else if (event.type === 'error') {
        append({ text: `Error: ${event.message}`, color: 'var(--danger, #ef4444)' });
      }
    }, controller.signal)
      .then(() => {
        if (finalResult) {
          setTitle('Discovery Complete');
          setStep(`${finalResult.links_discovered} links from ${finalResult.hosts_scanned} hosts`);
          append({ text: `── Done: ${finalResult.links_discovered} links, ${finalResult.hosts_scanned} hosts scanned, ${finalResult.errors} error(s)`, color: 'var(--primary-light)' });
        } else {
          setTitle('Discovery Finished');
          setStep('No results received');
        }
        onComplete();
      })
      .catch((err: Error) => {
        if (err.name === 'AbortError') return;
        append({ text: `Error: ${err.message}`, color: 'var(--danger, #ef4444)' });
      })
      .finally(() => {
        clearInterval(elapsedTimer);
        setRunning(false);
      });

    return () => {
      clearInterval(elapsedTimer);
      controller.abort();
    };
  }, [isOpen, groupId, onComplete]);

  function handleClose() {
    abortRef.current?.abort();
    onClose();
  }

  const elapsedStr = elapsed < 60 ? `${elapsed}s` : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`;
  const pct = total ? Math.round((scanned / total) * 100) : 0;

  return (
    <Modal isOpen={isOpen} onClose={handleClose} title="Neighbor Discovery" size="large">
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
        {running && <div className="discovery-spinner" />}
        <div>
          <div style={{ fontSize: '1rem', fontWeight: 600 }}>{title}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{subtitle}</div>
        </div>
      </div>
      <div style={{ marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
          <span>{scanned} / {total ?? '?'} hosts scanned</span>
          <span style={{ color: 'var(--primary-light)', fontWeight: 600 }}>{links} links found</span>
        </div>
        <div style={{ height: 6, background: 'var(--bg-secondary)', borderRadius: 3, overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${pct}%`, background: 'var(--primary)', borderRadius: 3, transition: 'width 0.15s ease' }} />
        </div>
      </div>
      <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '0.5rem' }}>
        Elapsed: {elapsedStr} · {step}
      </div>
      <div style={{ maxHeight: 220, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: '0.5rem', padding: '0.4rem 0.6rem', fontSize: '0.8rem', fontFamily: 'monospace', background: 'var(--bg-secondary)' }}>
        {feed.map((entry, i) => (
          <div key={i} style={{ padding: '0.15rem 0', borderBottom: '1px solid var(--border)', color: entry.color || 'var(--text-primary)' }}>
            {entry.text}
          </div>
        ))}
      </div>
    </Modal>
  );
}
