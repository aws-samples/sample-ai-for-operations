// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { AssetHashType, DockerImage, ILocalBundling } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SRC = path.join(REPO_ROOT, 'src');
const REQUIREMENTS = path.join(REPO_ROOT, 'requirements.txt');
const EXCLUDE = ['__pycache__', '**/__pycache__', '**/__pycache__/**', '**/*.pyc'];

// nosemgrep: detect-non-literal-fs-filename, path-join-resolve-traversal -- CDK synth-time packaging
// helper. `from`/`to` always originate as SRC = <this repo's own src/ dir> (see sourceHash below),
// never from external or user-supplied input; this walks the repository's own tree on the
// developer's/CI's machine, not a deployed runtime path.
function copyTree(from: string, to: string): void {
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) { // nosemgrep: detect-non-literal-fs-filename
    if (entry.name === '__pycache__' || entry.name.endsWith('.pyc')) continue;
    const src = path.join(from, entry.name); // nosemgrep: path-join-resolve-traversal
    const dst = path.join(to, entry.name); // nosemgrep: path-join-resolve-traversal
    if (entry.isDirectory()) {
      fs.mkdirSync(dst, { recursive: true }); // nosemgrep: detect-non-literal-fs-filename
      copyTree(src, dst);
    } else {
      fs.copyFileSync(src, dst); // nosemgrep: detect-non-literal-fs-filename
    }
  }
}

/**
 * Local bundling: pip-install the pinned requirements as arm64 Linux wheels, then copy src/.
 * Uses $PYTHON (deploy.sh sets it to the project venv) or python3. Arguments are passed as an
 * array (no shell). Falls back to Docker bundling if the local toolchain is unavailable.
 */
const localBundling: ILocalBundling = {
  tryBundle(outputDir: string): boolean {
    const python = process.env.PYTHON || 'python3';
    try {
      execFileSync(python, [
        '-m', 'pip', 'install', '--quiet', '--no-compile',
        '-r', REQUIREMENTS, '--target', outputDir,
        '--platform', 'manylinux2014_aarch64', '--implementation', 'cp', '--python-version', '3.12',
        '--only-binary=:all:',
      ], { stdio: 'inherit' });
    } catch {
      return false;
    }
    copyTree(SRC, outputDir);
    return true;
  },
};

// nosemgrep: detect-non-literal-fs-filename, path-join-resolve-traversal -- same as copyTree above:
// `dir` always originates from SRC (this repo's own src/), enumerated at CDK synth time, never
// from external or user-supplied input.
function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) { // nosemgrep: detect-non-literal-fs-filename
    if (entry.name === '__pycache__' || entry.name.endsWith('.pyc')) continue;
    const full = path.join(dir, entry.name); // nosemgrep: path-join-resolve-traversal
    if (entry.isDirectory()) out.push(...filesUnder(full));
    else out.push(full);
  }
  return out;
}

/**
 * Content hash of everything that ends up in the bundle: every file under src/ (path + bytes)
 * and requirements.txt. Used as the asset hash so ANY code or dependency change produces a new
 * asset. (A source fingerprint built from exclude globs silently stayed constant: glob ignores
 * cannot re-include files under an excluded directory, so CDK reused a stale bundle.)
 */
export function sourceHash(): string {
  const hash = crypto.createHash('sha256');
  for (const file of [...filesUnder(SRC), REQUIREMENTS].sort()) {
    hash.update(path.relative(REPO_ROOT, file).split(path.sep).join('/'));
    hash.update('\0');
    hash.update(fs.readFileSync(file));
    hash.update('\0');
  }
  return hash.digest('hex');
}

export function lambdaCode(skipBundling: boolean): lambda.Code {
  if (skipBundling) {
    return lambda.Code.fromAsset(SRC, { exclude: EXCLUDE });
  }
  return lambda.Code.fromAsset(REPO_ROOT, {
    assetHashType: AssetHashType.CUSTOM,
    assetHash: sourceHash(),
    exclude: ['**', '!src/**', '!requirements.txt', ...EXCLUDE],
    bundling: {
      local: localBundling,
      image: DockerImage.fromRegistry('public.ecr.aws/sam/build-python3.12:latest-arm64'),
      command: ['bash', '-c', 'pip install --no-compile -r requirements.txt -t /asset-output && cp -r src/. /asset-output'],
    },
  });
}
