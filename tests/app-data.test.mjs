import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { emptyFilters, readState, stateQuery, makeCatalog, filterApps, compareScopes, GRAPH } from '../app-data.mjs';

const read = name => JSON.parse(readFileSync(new URL(`../${name}`, import.meta.url), 'utf8'));
const raw = read('firstpartyscopes.json');
const catalog = makeCatalog(raw, read('resources.json'), read('bypasses.json'), read('Classification_AppRoles.json'), read('authcodefix.json'));

test('all current application records are indexed without changing the dataset', () => {
  assert.equal(catalog.apps.length, Object.keys(raw.apps).length);
  for (const app of catalog.apps) {
    assert.equal(app.scopeCount, Object.values(raw.apps[app.id].scopes).flat().length);
    assert.deepEqual(app.redirect_uris, raw.apps[app.id].redirect_uris);
  }
});
test('multiple app, resource and scope selections survive a shared URL', () => {
  const filters = { ...emptyFilters(), search: 'Azure & Teams', foci: 'false', naa: 'true', apps: catalog.apps.slice(0, 2).map(a => a.id), resources: catalog.resources.slice(0, 2), scopes: ['User.Read', 'openid'] };
  const compare = catalog.apps.slice(2, 4).map(a => a.id);
  const view = catalog.apps[4].id;
  assert.deepEqual(readState(stateQuery(filters, view, compare)), { filters, view, compare });
});
test('legacy app detail URLs and multiple-app URLs remain distinct', () => {
  assert.equal(readState('?appId=a').view, 'a');
  assert.deepEqual(readState('?appId=a&appId=b').filters.apps, ['a', 'b']);
  assert.equal(readState('?appId=a&appId=b').view, '');
  assert.equal(readState('?app=a').view, '');
});
test('application search matches a pasted ID and ignores surrounding whitespace', () => {
  const app = catalog.apps[5];
  assert.deepEqual(filterApps(catalog.apps, { ...emptyFilters(), search: ` ${app.id.toUpperCase()} ` }).map(a => a.id), [app.id]);
});
test('resource and scope filters match scopes within the chosen resource', () => {
  const results = filterApps(catalog.apps, { ...emptyFilters(), resources: [GRAPH], scopes: ['User.Read'] });
  assert.ok(results.length > 0);
  assert.ok(results.every(a => a.scopes[GRAPH]?.includes('User.Read')));
  assert.equal(filterApps(catalog.apps, { ...emptyFilters(), resources: [GRAPH, 'unknown-resource'], scopes: ['User.Read'] }).length, 0);
});
test('resetting all filters includes applications with and without broker redirects', () => {
  assert.equal(filterApps(catalog.apps, emptyFilters()).length, catalog.apps.length);
  for (const value of ['true', 'false']) {
    const results = filterApps(catalog.apps, { ...emptyFilters(), naa: value });
    assert.ok(results.length > 0);
    assert.ok(results.every(a => a.hasNaa === (value === 'true')));
  }
});
test('mitigated bypasses are retained as findings without counting as active', () => {
  const data = { apps: { a: { name: 'App', scopes: {}, redirect_uris: [] } } };
  const c = makeCatalog(data, [], [{ AppID: 'a', CurrentState: 'Mitigated' }], [], []);
  assert.equal(c.apps[0].bypasses.length, 1);
  assert.equal(filterApps(c.apps, { ...emptyFilters(), bypass: 'true' }).length, 0);
});
test('comparison separates shared and unique scopes and does not mutate inputs', () => {
  const a = { scopes: { r: ['b', 'a'] } }, b = { scopes: { r: ['c', 'b'] } };
  assert.deepEqual(compareScopes(a, b, 'r'), { common: ['b'], left: ['a'], right: ['c'] });
  assert.deepEqual(a.scopes.r, ['b', 'a']);
  assert.deepEqual(compareScopes(a, b, 'missing'), { common: [], left: [], right: [] });
});
