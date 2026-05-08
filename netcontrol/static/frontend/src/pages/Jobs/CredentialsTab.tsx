import { useState } from 'react';

import { CredentialsList } from './CredentialsList';
import { SecretVariablesList } from './SecretVariablesList';

type Subtab = 'credentials' | 'secrets';

export function CredentialsTab() {
  const [sub, setSub] = useState<Subtab>('credentials');

  return (
    <div>
      <div className="tab-bar" role="tablist" style={{ marginBottom: '1rem' }}>
        <button
          role="tab"
          aria-selected={sub === 'credentials'}
          className={`tab-btn${sub === 'credentials' ? ' active' : ''}`}
          onClick={() => setSub('credentials')}
        >
          Credentials
        </button>
        <button
          role="tab"
          aria-selected={sub === 'secrets'}
          className={`tab-btn${sub === 'secrets' ? ' active' : ''}`}
          onClick={() => setSub('secrets')}
        >
          Secret Variables
        </button>
      </div>

      {sub === 'credentials' ? <CredentialsList /> : <SecretVariablesList />}
    </div>
  );
}
