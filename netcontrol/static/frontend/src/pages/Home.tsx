import {
  Alert,
  Bullseye,
  Card,
  CardBody,
  CardTitle,
  Content,
  Spinner,
  Stack,
  StackItem,
  Title,
} from '@patternfly/react-core';

import { useAuthStatus } from '@/api/auth';

export function Home() {
  const { data, isPending, error } = useAuthStatus();

  return (
    <Stack hasGutter>
      <StackItem>
        <Title headingLevel="h1" size="2xl">
          Plexus — React Frontend
        </Title>
        <Content component="p">
          Phase 1.1 skeleton. Vite + React 18 + TypeScript + PatternFly +
          TanStack Query, served by FastAPI at <code>/frontend/</code>.
        </Content>
      </StackItem>

      <StackItem>
        <Card>
          <CardTitle>Backend connectivity</CardTitle>
          <CardBody>
            {isPending && (
              <Bullseye>
                <Spinner size="lg" aria-label="Checking auth status" />
              </Bullseye>
            )}
            {error && (
              <Alert variant="danger" title="Auth status request failed" isInline>
                {error.message}
              </Alert>
            )}
            {data && (
              <Alert
                variant={data.authenticated ? 'success' : 'warning'}
                title={
                  data.authenticated
                    ? `Authenticated as ${data.username ?? 'unknown user'}`
                    : 'Not authenticated'
                }
                isInline
              >
                <pre style={{ margin: 0, fontSize: '0.85em' }}>
                  {JSON.stringify(data, null, 2)}
                </pre>
              </Alert>
            )}
          </CardBody>
        </Card>
      </StackItem>
    </Stack>
  );
}
