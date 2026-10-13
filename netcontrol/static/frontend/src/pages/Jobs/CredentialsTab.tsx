import { useState } from 'react';

import { TabBar } from '@/components/TabBar';

import { CredentialsList } from './CredentialsList';
import { SecretVariablesList } from './SecretVariablesList';

type Subtab = 'credentials' | 'secrets';

const SUBTABS: { key: Subtab; label: string }[] = [
  { key: 'credentials', label: 'Credentials' },
  { key: 'secrets', label: 'Secret Variables' },
];

export function CredentialsTab() {
  const [sub, setSub] = useState<Subtab>('credentials');

  return (
    <div>
      <TabBar
        tabs={SUBTABS}
        active={sub}
        onChange={setSub}
        size="sm"
        aria-label="Credential types"
      />

      {sub === 'credentials' ? <CredentialsList /> : <SecretVariablesList />}
    </div>
  );
}
