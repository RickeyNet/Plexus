Extra CA certificates the Docker image build trusts.

Drop PEM-encoded CA certificates here as *.crt files (one certificate per
file) when the build host sits behind a TLS-inspecting proxy (Cato, Zscaler,
Netskope, Palo Alto, ...) that re-signs outbound HTTPS with its own CA. The
symptom is an image build failing with

    SSL connection failed: error:0A000086:SSL routines::certificate verify failed

on deb.debian.org, github.com or similar, while the same URLs open fine in a
browser on the host (which already trusts the proxy's root CA).

Every build stage trusts the files here: apt, pip and the Pyodide fetch read
them from the system store, npm through NODE_EXTRA_CA_CERTS. The directory is
part of the build context and is empty by default; *.crt files in it are
ignored by git, so they stay on the build host. This file is only here so the
directory exists for COPY.

Export the root CA from the host's trust store, for example on Windows:

    $c = Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -match 'Cato Networks Root CA'
    $b = [Convert]::ToBase64String($c.RawData) -replace '.{64}', "`$&`n"
    "-----BEGIN CERTIFICATE-----`n$b`n-----END CERTIFICATE-----" | Set-Content deploy\build-ca\proxy-root-ca.crt

or on Linux copy the file from /usr/local/share/ca-certificates/.
