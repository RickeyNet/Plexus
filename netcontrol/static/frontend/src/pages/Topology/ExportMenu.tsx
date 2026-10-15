import { ExportMenu as SharedExportMenu, type ExportMenuItem } from '@/components/ExportMenu';

interface Props {
  onPNG: () => void;
  onSVG: () => void;
  onJSON: () => void;
  /** Interactive HTML map, sent as a file download. */
  htmlDownloadUrl: string;
  /** The same map rendered inline, for a new browser tab. */
  htmlOpenUrl: string;
  /** The HTML map carries the Path Mode path open on the page, with its traces. */
  withPath?: boolean;
}

const PATH_NOTE = ' Includes the open path with its traces.';

/** One toolbar button that opens every topology export, each with a short description. */
export function ExportMenu({ onPNG, onSVG, onJSON, htmlDownloadUrl, htmlOpenUrl, withPath = false }: Props) {
  const pathNote = withPath ? PATH_NOTE : '';
  const items: ExportMenuItem[] = [
    {
      label: 'PNG image',
      description: 'High-resolution snapshot of the whole map with a title header. Good for slides and tickets.',
      onClick: onPNG,
    },
    {
      label: 'SVG drawing',
      description: 'Devices, links and port labels as a vector drawing that stays sharp at any size and can be edited.',
      onClick: onSVG,
    },
    {
      label: 'JSON data',
      description: 'The raw nodes and links behind the map, for scripts or loading into other tools.',
      onClick: onJSON,
    },
    {
      label: withPath ? 'HTML map with path (download)' : 'HTML map (download)',
      description: `One self-contained, interactive file with every device's details. Opens in any browser, no Plexus login needed.${pathNote}`,
      href: htmlDownloadUrl,
      download: true,
    },
    {
      label: withPath ? 'Open HTML map with path' : 'Open HTML map',
      description: `The same interactive map in a new browser tab, without saving a file.${pathNote}`,
      href: htmlOpenUrl,
    },
  ];

  return <SharedExportMenu items={items} width={320} />;
}
