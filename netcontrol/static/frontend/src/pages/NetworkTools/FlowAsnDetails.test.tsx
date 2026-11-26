import { renderToStaticMarkup } from 'react-dom/server';
import { expect, it } from 'vitest';

import { FlowTalkerAddress } from './FlowAsnDetails';

const row = { ip: '1.1.1.1', flow_count: 4, total_bytes: 1024 };

it('keeps the IP visible and renders the operator as text', () => {
  const html = renderToStaticMarkup(<FlowTalkerAddress row={{ ...row, asn: 13335, asn_organization: '<Example>' }} />);
  expect(html).toContain('<code>1.1.1.1</code>');
  expect(html).toContain('&lt;Example&gt; (AS13335)');
});

it('shows the ASN alone if no operator name was supplied', () => {
  expect(renderToStaticMarkup(<FlowTalkerAddress row={{ ...row, asn: 13335 }} />)).toContain('AS13335');
});

it('shows only the IP without ASN data', () => {
  expect(renderToStaticMarkup(<FlowTalkerAddress row={row} />)).toBe('<code>1.1.1.1</code>');
});
