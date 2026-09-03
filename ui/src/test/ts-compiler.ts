/**
 * TypeScript 7 test-side AST adapter.
 *
 * TypeScript 7 moved parsing behind the native compiler snapshot API while keeping
 * node types and guards in `unstable/ast`.  Polaris' structural tests only need a
 * parsed SourceFile, so keep that migration boundary here instead of teaching each
 * invariant test how to create and tear down a compiler session.
 */
import { API } from 'typescript/unstable/sync';
import { createVirtualFileSystem } from 'typescript/unstable/fs';
import type { Node, SourceFile } from 'typescript/unstable/ast';
import { afterAll } from 'vitest';
import { resolve } from 'node:path';

export * from 'typescript/unstable/ast';

const CONFIG_PATH = resolve(process.cwd(), 'tsconfig.json');
const api = new API({ cwd: process.cwd() });
const snapshot = api.updateSnapshot({ openProject: CONFIG_PATH });
const openedProject = snapshot.getProject(CONFIG_PATH);
let closed = false;

function closeProject(): void {
  if (closed) return;
  closed = true;
  snapshot.dispose();
  api.close();
}

if (!openedProject) {
  closeProject();
  throw new Error(`TypeScript failed to open ${CONFIG_PATH}`);
}
const project = openedProject;

afterAll(closeProject);

export function parseSourceFile(fileName: string, text: string): SourceFile {
  const sourceFile = project.program.getSourceFile(resolve(fileName));
  if (!sourceFile) return parseVirtual(fileName, text);
  if (sourceFile.text !== text) throw new Error(`TypeScript snapshot is stale for ${fileName}`);
  return sourceFile;
}

function parseVirtual(fileName: string, text: string): SourceFile {
  const sourcePath = `/${fileName.replaceAll('\\', '/').replace(/^\/+/, '')}`;
  const configPath = '/tsconfig.json';
  const virtualApi = new API({
    cwd: process.cwd(),
    fs: createVirtualFileSystem({
      [configPath]: JSON.stringify({
        compilerOptions: { allowJs: true, jsx: 'preserve', noLib: true },
        files: [sourcePath],
      }),
      [sourcePath]: text,
    }),
  });
  try {
    const virtualSnapshot = virtualApi.updateSnapshot({ openProject: configPath });
    try {
      const parsed = virtualSnapshot.getProject(configPath)?.program.getSourceFile(sourcePath);
      if (!parsed) throw new Error(`TypeScript failed to parse ${fileName}`);
      return parsed;
    } finally {
      virtualSnapshot.dispose();
    }
  } finally {
    virtualApi.close();
  }
}

export function forEachChild<T>(node: Node, visitor: (child: Node) => T): T | undefined {
  return node.forEachChild(visitor);
}
