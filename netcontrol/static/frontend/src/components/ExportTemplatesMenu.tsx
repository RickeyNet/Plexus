import { type ExportObjectType, exportTemplateRenderUrl, useExportTemplates } from '@/api/exportTemplates';

import { ExportMenu, type ExportMenuItem } from './ExportMenu';

interface Props {
  objectType: ExportObjectType;
  /** The list's current filters, passed to the render (see `exportTemplateRenderUrl`). */
  params?: Parameters<typeof exportTemplateRenderUrl>[1];
  label?: string;
}

/**
 * "Export ▾" with one item per export template bound to `objectType`; each
 * renders the template with the objects the caller may read, after
 * `params`. Renders nothing while loading, on error, or with no template.
 */
export function ExportTemplatesMenu({ objectType, params, label = 'Export' }: Props) {
  const templates = useExportTemplates(objectType).data?.templates ?? [];
  const items: ExportMenuItem[] = templates.map((t) => ({
    label: t.name,
    description: t.description || (t.file_extension ? `.${t.file_extension} file` : t.mime_type),
    href: exportTemplateRenderUrl(t.id, params),
    download: t.as_attachment,
  }));
  return <ExportMenu items={items} label={label} width={280} />;
}
