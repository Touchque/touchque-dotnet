# Contributing

Thanks for considering a contribution to `TouchQue` and `TouchQue.AspNetCore` (.NET).

## Setup

You need the .NET 8 SDK and Node.js 20 or later.

```bash
dotnet build -c Release
```

## Running tests

```bash
dotnet test -c Release
```

Many suites run **contract tests** against `testing/fake-touchque-api.mjs` — a
small, dependency-free Node server that verifies the SDK's HMAC request
signatures exactly like the real API does. They need `node` on `PATH`; without
it they fail instead of skipping.

## Making a change

1. If it touches the wire protocol or the step-up contract, update the
   fixtures in `fixtures/` and the fake API in `testing/` first.
2. Add tests. A behavior change without a test won't be merged.
3. Update `CHANGELOG.md` (Keep a Changelog format) under `## [Unreleased]`.
4. Keep code, comments, docs and error messages in English.
5. Keep the build warning-free: warnings are errors (`TreatWarningsAsErrors`
   in `Directory.Build.props`).

## Pull requests

- Describe what changed and why, not just what. If it's a breaking change,
  say so explicitly and explain the migration.
- CI must pass.

## Reporting a security issue

Please don't open a public issue — see [SECURITY.md](./SECURITY.md).
