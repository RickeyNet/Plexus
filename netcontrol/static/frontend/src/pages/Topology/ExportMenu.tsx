import { ExportMenu as SharedExportMenu, type ExportMenuItem } from '@/components/ExportMenu';

interface Props {
  onPNG: () => void;
  onSVG: () => void;
  onJSON: () => void;
  /** Interactive HTML map, sent as a file download. */
  htmlDownloadUrl: string;
  /** The same map rendered inline, for a new browser tab. */
  htmlOpenUrl: string;
}

/** One toolbar button that opens every topology export, each with a short description. */
export function ExportMenu({ onPNG, onSVG, onJSON, htmlDownloadUrl, htmlOpenUrl }: Props) {
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
      label: 'HTML map (download)',
      description: "One self-contained, interactive file with every device's details. Opens in any browser, no Plexus login needed.",
      href: htmlDownloadUrl,
      download: true,
    },
    {
      label: 'Open HTML map',
      description: 'The same interactive map in a new browser tab, without saving a file.',
      href: htmlOpenUrl,
    },
  ];

  return <SharedExportMenu items={items} width={320} />;
}
