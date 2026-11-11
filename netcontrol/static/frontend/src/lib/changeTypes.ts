/** Change types shared by deployments and risk analyses. */
const CHANGE_TYPE_LABELS: Record<string, string> = {
  template: 'Template',
  manual: 'Manual',
  policy: 'Policy / ACL',
  route: 'Route',
  nat: 'NAT',
};

/** Display text for a stored change type; unknown values pass through, missing is "-". */
export function changeTypeLabel(changeType: string | null | undefined): string {
  if (!changeType) return '-';
  return CHANGE_TYPE_LABELS[changeType] ?? changeType;
}

/** Select options for the given change types, in the order given. */
export function changeTypeOptions(values: string[]): { value: string; label: string }[] {
  return values.map((value) => ({ value, label: changeTypeLabel(value) }));
}
