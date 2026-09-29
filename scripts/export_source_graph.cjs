#!/usr/bin/env node
/* Export a deterministic JS/TS source manifest for Neo4j ingestion.
 * Run after `npm ci --prefix frontend`; no source text or secrets are exported.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { createRequire } = require('node:module');

const root = path.resolve(__dirname, '..');
const ts = createRequire(path.join(root, 'frontend/package.json'))('typescript');
const organizationId = Number(process.env.GRAPH_ORGANIZATION_ID);
if (!Number.isInteger(organizationId) || organizationId < 1) {
  throw new Error('Set GRAPH_ORGANIZATION_ID to a positive integer');
}
const repository = process.env.GRAPH_REPOSITORY || 'judahsecurity/judahsecurity';
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
const roots = (process.env.GRAPH_SOURCE_ROOTS || 'frontend/src,website/src')
  .split(',').map((item) => item.trim()).filter(Boolean);
const extensions = ['.ts', '.tsx', '.js', '.jsx'];
const dirtySources = execFileSync('git',
  ['status', '--porcelain', '--', ...roots, 'frontend/package-lock.json', 'website/package-lock.json'],
  { cwd: root, encoding: 'utf8' }).trim();
if (dirtySources) throw new Error('Commit source files and the lockfile before exporting the graph');

function listSourceFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.next') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listSourceFiles(full));
    else if (extensions.includes(path.extname(entry.name))) out.push(full);
  }
  return out;
}

function relativePath(full) {
  return path.relative(root, full).split(path.sep).join('/');
}

function resolveImport(from, specifier) {
  if (!specifier.startsWith('.') && !specifier.startsWith('@/')) return null;
  const base = specifier.startsWith('@/')
    ? path.resolve(root, 'frontend/src', specifier.slice(2))
    : path.resolve(path.dirname(from), specifier);
  for (const candidate of [base, ...extensions.map((ext) => base + ext),
    ...extensions.map((ext) => path.join(base, 'index' + ext))]) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile() &&
        !relativePath(candidate).startsWith('..')) return relativePath(candidate);
  }
  return null;
}

const locks = Object.fromEntries(['frontend', 'website'].map((name) => {
  const lockPath = path.join(root, name, 'package-lock.json');
  return [name, fs.existsSync(lockPath) ? JSON.parse(fs.readFileSync(lockPath, 'utf8')) : {}];
}));
function packageVersion(name, filePath) {
  const project = filePath.split('/')[0];
  return locks[project]?.packages?.[`node_modules/${name}`]?.version || null;
}

function routesForFile(filePath, symbols) {
  const match = filePath.match(/^(?:frontend|website)\/src\/app\/(.*\/)?(page|route)\.[jt]sx?$/);
  if (!match) return [];
  const segments = (match[1] || '').split('/').filter(Boolean)
    .filter((segment) => !/^\(.*\)$/.test(segment) && !segment.startsWith('@'))
    .map((segment) => segment.replace(/^\[\.\.\.(.+)\]$/, ':$1*')
      .replace(/^\[\[\.\.\.(.+)\]\]$/, ':$1*')
      .replace(/^\[(.+)\]$/, ':$1'));
  const routePath = '/' + segments.join('/');
  if (match[2] === 'page') return [{ path: routePath, method: 'GET' }];
  const methods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
  return symbols.filter((symbol) => methods.has(symbol.name))
    .map((symbol) => ({ path: routePath, method: symbol.name }));
}

const files = [];
for (const sourcePath of roots.flatMap((item) => listSourceFiles(path.join(root, item))).sort()) {
  const content = fs.readFileSync(sourcePath, 'utf8');
  const source = ts.createSourceFile(sourcePath, content, ts.ScriptTarget.Latest, true,
    sourcePath.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const symbols = [];
  const imports = [];
  const addSymbol = (name, kind, node) => {
    if (name) symbols.push({ name, kind, line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1 });
  };
  for (const statement of source.statements) {
    if ((ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) &&
        statement.moduleSpecifier && ts.isStringLiteral(statement.moduleSpecifier)) {
      const specifier = statement.moduleSpecifier.text;
      const resolvedPath = resolveImport(sourcePath, specifier);
      const packageName = resolvedPath || specifier.startsWith('.') || specifier.startsWith('@/') ? null :
        (specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0]);
      imports.push({ specifier, resolved_path: resolvedPath,
        package_name: packageName,
        version: packageName ? packageVersion(packageName, relativePath(sourcePath)) : null });
    }
    if (ts.isFunctionDeclaration(statement)) addSymbol(statement.name?.text || 'default', 'function', statement);
    else if (ts.isClassDeclaration(statement)) addSymbol(statement.name?.text || 'default', 'class', statement);
    else if (ts.isInterfaceDeclaration(statement)) addSymbol(statement.name.text, 'interface', statement);
    else if (ts.isTypeAliasDeclaration(statement)) addSymbol(statement.name.text, 'type', statement);
    else if (ts.isEnumDeclaration(statement)) addSymbol(statement.name.text, 'enum', statement);
    else if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) addSymbol(declaration.name.text, 'variable', declaration);
      }
    }
  }
  const filePath = relativePath(sourcePath);
  files.push({ path: filePath, sha256: crypto.createHash('sha256').update(content).digest('hex'),
    language: path.extname(sourcePath).slice(1), symbols, imports,
    routes: routesForFile(filePath, symbols) });
}

const manifest = { schema_version: 1, organization_id: organizationId, repository, commit,
  files, bundle_mappings: [] };
process.stdout.write(JSON.stringify(manifest));
