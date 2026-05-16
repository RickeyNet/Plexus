import { useState } from 'react';

import { CredentialsList } from './CredentialsList';
import { SecretVariablesList } from './SecretVariablesList';

type Subtab = 'credentials' | 'secrets';

export function CredentialsTab() {
  const [sub, setSub] = useState<Subtab>('credentials');

  return (
    <div>
      {/* Match the parent Delegator tab row exactly: tab-bar/tab-btn
          are not defined in the legacy stylesheet, so they rendered as
          bare unstyled boxes. btn btn-sm btn-secondary + mon-tab-btn is
          the established working convention (see Jobs.tsx). */}
      <div role="tablist" style={{ marginBottom: '1rem', display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
        <button
          role="tab"
          aria-selected={sub === 'credentials'}
          className={`btn btn-sm btn-secondary mon-tab-btn${sub === 'credentials' ? ' active' : ''}`}
          onClick={() => setSub('credentials')}
        >
          Credentials
        </button>
        <button
          role="tab"
          aria-selected={sub === 'secrets'}
          className={`btn btn-sm btn-secondary mon-tab-btn${sub === 'secrets' ? ' active' : ''}`}
          onClick={() => setSub('secrets')}
        >
          Secret Variables
        </button>
      </div>

      {sub === 'credentials' ? <CredentialsList /> : <SecretVariablesList />}
    </div>
  );
}
