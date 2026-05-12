import type { Network } from 'vis-network';

import type { TopologyData } from '@/api/topology';
import type { TopoThemeColors } from './helpers';
import { abbreviateInterface } from './helpers';

function svgEscape(str: string): string {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function exportPNG(network: Network, groupName: string): void {
  const canvasContainer = document.getElementById('topology-canvas');
  const canvas = canvasContainer?.querySelector('canvas');
  if (!canvas) throw new Error('Canvas not found');

  const scale = 3;
  const origW = canvas.width;
  const origH = canvas.height;
  const headerHeight = 60 * scale;

  const out = document.createElement('canvas');
  out.width = origW * scale;
  out.height = origH * scale + headerHeight;
  const ctx = out.getContext('2d');
  if (!ctx) throw new Error('Cannot get 2d context');

  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, out.width, out.height);
  ctx.fillStyle = '#f5f5f5';
  ctx.fillRect(0, 0, out.width, headerHeight);
  ctx.fillStyle = '#333';
  ctx.font = `bold ${20 * scale}px Inter, sans-serif`;
  ctx.textAlign = 'center';
  ctx.fillText(`Network Topology - ${groupName}`, out.width / 2, 28 * scale);
  ctx.font = `${13 * scale}px Inter, sans-serif`;
  ctx.fillStyle = '#888';
  ctx.fillText(new Date().toLocaleDateString(), out.width / 2, 48 * scale);

  const hiRes = document.createElement('canvas');
  hiRes.width = origW * scale;
  hiRes.height = origH * scale;
  const hiCtx = hiRes.getContext('2d');
  if (!hiCtx) throw new Error('Cannot get hi-res context');
  hiCtx.scale(scale, scale);

  const positions = network.getPositions();
  const posVals = Object.values(positions);
  let bb: { minX: number; minY: number; maxX: number; maxY: number } | null = null;
  if (posVals.length > 0) {
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const p of posVals) {
      minX = Math.min(minX, p.x);
      minY = Math.min(minY, p.y);
      maxX = Math.max(maxX, p.x);
      maxY = Math.max(maxY, p.y);
    }
    bb = { minX, minY, maxX, maxY };
  }

  if (bb && Number.isFinite(bb.minX)) {
    const pad = 80;
    const nw = bb.maxX - bb.minX + pad * 2;
    const nh = bb.maxY - bb.minY + pad * 2;
    const fitScale = Math.min(origW / nw, origH / nh, 1.5);
    const cx = (bb.minX + bb.maxX) / 2;
    const cy = (bb.minY + bb.maxY) / 2;
    const origView = network.getViewPosition();
    const origScale = network.getScale();
    network.moveTo({ position: { x: cx, y: cy }, scale: fitScale, animation: false });
    network.redraw();
    hiCtx.drawImage(canvas, 0, 0);
    ctx.drawImage(hiRes, 0, headerHeight);
    network.moveTo({ position: origView, scale: origScale, animation: false });
    network.redraw();
  } else {
    hiCtx.drawImage(canvas, 0, 0);
    ctx.drawImage(hiRes, 0, headerHeight);
  }

  const link = document.createElement('a');
  link.download = `topology-${new Date().toISOString().slice(0, 10)}.png`;
  link.href = out.toDataURL('image/png');
  link.click();
}

export function exportJSON(data: TopologyData): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.download = `topology-${new Date().toISOString().slice(0, 10)}.json`;
  link.href = URL.createObjectURL(blob);
  link.click();
  URL.revokeObjectURL(link.href);
}

export function exportSVG(network: Network, data: TopologyData, groupName: string, _tc: TopoThemeColors): void {
  const positions = network.getPositions();
  const nodeMap: Record<string, typeof data.nodes[number]> = {};
  for (const n of data.nodes) nodeMap[String(n.id)] = n;

  const posArray = Object.values(positions);
  if (!posArray.length) throw new Error('No nodes to export');
  const margin = 80;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  posArray.forEach((p) => {
    if (p.x < minX) minX = p.x;
    if (p.y < minY) minY = p.y;
    if (p.x > maxX) maxX = p.x;
    if (p.y > maxY) maxY = p.y;
  });
  const width = maxX - minX + margin * 2;
  const height = maxY - minY + margin * 2;
  const ox = -minX + margin;
  const oy = -minY + margin;

  const protoColor: Record<string, string> = {
    cdp: '#00b0ff',
    lldp: '#00e676',
    ospf: '#ffab40',
    bgp: '#e040fb',
    'inferred-fdb': '#9e9e9e',
  };

  let edgeSvg = '';
  for (const e of data.edges) {
    const fp = positions[e.from as never];
    const tp = positions[e.to as never];
    if (!fp || !tp) continue;
    const proto = (e.protocol || 'cdp').toLowerCase();
    const color = protoColor[proto] || '#888';
    const dash = proto === 'lldp' ? ' stroke-dasharray="8 5"' : proto === 'ospf' ? ' stroke-dasharray="12 4 4 4"' : proto === 'bgp' ? ' stroke-dasharray="4 4"' : proto === 'inferred-fdb' ? ' stroke-dasharray="2 4"' : '';
    edgeSvg += `<line x1="${fp.x + ox}" y1="${fp.y + oy}" x2="${tp.x + ox}" y2="${tp.y + oy}" stroke="${color}" stroke-width="2"${dash} opacity="0.7"/>`;
    const lbl = [abbreviateInterface(e.source_interface), abbreviateInterface(e.target_interface)].filter(Boolean).join(' → ');
    if (lbl) {
      const mx = (fp.x + tp.x) / 2 + ox;
      const my = (fp.y + tp.y) / 2 + oy;
      edgeSvg += `<text x="${mx}" y="${my - 4}" text-anchor="middle" font-size="8" fill="#999" font-family="Inter, sans-serif">${svgEscape(lbl)}</text>`;
    }
  }

  let nodeSvg = '';
  for (const [idStr, pos] of Object.entries(positions)) {
    const n = nodeMap[idStr];
    if (!n) continue;
    const cx = pos.x + ox;
    const cy = pos.y + oy;
    const r = n.in_inventory ? 20 : 14;
    const fill = n.in_inventory ? '#607D8B' : 'none';
    const stroke = n.in_inventory ? '#fff' : '#999';
    const dashAttr = n.in_inventory ? '' : ' stroke-dasharray="5 5"';
    nodeSvg += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${fill}" stroke="${stroke}" stroke-width="2"${dashAttr}/>`;
    nodeSvg += `<text x="${cx}" y="${cy + r + 14}" text-anchor="middle" font-size="11" fill="#ddd" font-family="Inter, sans-serif">${svgEscape(n.label)}</text>`;
  }

  const dateStr = new Date().toLocaleDateString();
  const titleSvg = `<text x="${width / 2}" y="24" text-anchor="middle" font-size="16" font-weight="bold" fill="#ccc" font-family="Inter, sans-serif">Network Topology - ${svgEscape(groupName)} - ${dateStr}</text>`;

  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height + 40}" viewBox="0 0 ${width} ${height + 40}">
<rect width="100%" height="100%" fill="#1a1a2e"/>
<g transform="translate(0,40)">
${titleSvg}
${edgeSvg}
${nodeSvg}
</g>
</svg>`;

  const blob = new Blob([svg], { type: 'image/svg+xml' });
  const link = document.createElement('a');
  link.download = `topology-${new Date().toISOString().slice(0, 10)}.svg`;
  link.href = URL.createObjectURL(blob);
  link.click();
  URL.revokeObjectURL(link.href);
}
