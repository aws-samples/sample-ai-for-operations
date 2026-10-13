# Infrastructure

CDK v2 infrastructure for the AWS Health Event Triage Agent.

## Dependencies

The `package.json` uses version ranges (e.g., `2.*`, `22.*`) which is standard practice for CDK projects. Exact versions are locked in `package-lock.json` to ensure reproducible builds. This addresses the Semgrep `package-dependencies-check` warnings - the ranges are safe due to the lock file.

## Building

```bash
npm install
npm run build
npm run synth
```

## Deploying

```bash
npm run deploy
```