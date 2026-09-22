export const GRAPH = '00000003-0000-0000-c000-000000000000';
export const booleanFilters = ['foci', 'clientType', 'naa', 'bypass', 'authcodeFix'];
export function emptyFilters() {
  return { search: '', foci: '', clientType: '', naa: '', bypass: '', authcodeFix: '', apps: [], resources: [], scopes: [] };
}
export function readState(search) {
  const p = new URLSearchParams(search), filters = emptyFilters();
  filters.search = p.get('search') || '';
  for (const key of booleanFilters) filters[key] = ['true', 'false'].includes(p.get(key)) ? p.get(key) : '';
  filters.apps = [...new Set(p.getAll('app'))];
  filters.resources = [...new Set(p.getAll('resource'))];
  filters.scopes = [...new Set(p.getAll('scope'))];
  const legacyApps = p.getAll('appId');
  if (legacyApps.length > 1) filters.apps = legacyApps;
  return { filters, view: p.get('view') || (legacyApps.length === 1 ? legacyApps[0] : ''), compare: [...new Set(p.getAll('compare'))].slice(0, 2) };
}
export function stateQuery(filters, view = '', compare = []) {
  const p = new URLSearchParams();
  for (const key of ['search', ...booleanFilters]) if (filters[key]) p.set(key, filters[key]);
  for (const [key, param] of [['apps', 'app'], ['resources', 'resource'], ['scopes', 'scope']]) filters[key].forEach(value => p.append(param, value));
  if (view) p.set('view', view);
  compare.forEach(id => p.append('compare', id));
  return p.toString() ? `?${p}` : '';
}
export function makeCatalog(data, resources, bypasses, classifications, authcodeFix) {
  if (!data.apps || !Array.isArray(resources) || !Array.isArray(bypasses) || !Array.isArray(classifications) || !Array.isArray(authcodeFix)) throw new Error('One of the datasets has an unexpected format.');
  const resourceNames = new Map(resources.map(r => [r.resourceId, r.displayName]));
  const tiers = new Map(classifications.map(c => [`${c.AppId}:${c.AppRoleDisplayName}`, c.EAMTierLevelName]));
  const fixes = new Map();
  for (const item of authcodeFix) fixes.set(item.AppId, [...(fixes.get(item.AppId) || []), item]);
  const apps = Object.entries(data.apps).map(([id, app]) => {
    const resourceIds = Object.keys(app.scopes || {});
    const resourceEntries = Object.entries(app.scopes || {}).sort(([a], [b]) => a === b ? 0 : a === GRAPH ? -1 : b === GRAPH ? 1 : (resourceNames.get(a) || a).localeCompare(resourceNames.get(b) || b));
    const matches = bypasses.filter(b => b.AppID === id || b.AppID === '*' && b.ResourcesAndScopes.some(rs => Object.entries(rs).some(([r, scopes]) => scopes.some(s => s.split(/\s+/).some(scope => app.scopes?.[r]?.includes(scope))))));
    return { ...app, id, name: app.name || id, redirect_uris: app.redirect_uris || [], resourceIds, resourceEntries,
      scopeCount: Object.values(app.scopes || {}).flat().length, scopeSet: new Set(Object.values(app.scopes || {}).flat()),
      hasNaa: (app.redirect_uris || []).some(uri => /^brk-/i.test(uri)), bypasses: matches,
      activeBypasses: matches.filter(b => !/^mitigated$/i.test(b.CurrentState)), authcodeFix: fixes.get(id) || [], searchText: `${app.name} ${id}`.toLowerCase() };
  }).sort((a, b) => a.name.localeCompare(b.name));
  return { apps, byId: new Map(apps.map(a => [a.id, a])), resourceNames, tiers,
    resources: [...new Set(apps.flatMap(a => a.resourceIds))].sort((a, b) => a === b ? 0 : a === GRAPH ? -1 : b === GRAPH ? 1 : (resourceNames.get(a) || a).localeCompare(resourceNames.get(b) || b)),
    scopes: [...new Set(apps.flatMap(a => [...a.scopeSet]))].sort() };
}
export function filterApps(apps, f) {
  const query = f.search.trim().toLowerCase();
  const bool = (value, selected) => !selected || Boolean(value) === (selected === 'true');
  return apps.filter(a => a.searchText.includes(query) && bool(a.foci, f.foci) && bool(a.public_client, f.clientType) && bool(a.hasNaa, f.naa)
    && bool(a.activeBypasses.length, f.bypass) && bool(a.authcodeFix.length, f.authcodeFix)
    && (!f.apps.length || f.apps.includes(a.id)) && (!f.resources.length || f.resources.some(r => a.resourceIds.includes(r)))
    && (!f.scopes.length || (f.resources.length ? f.resources.every(r => f.scopes.some(s => a.scopes[r]?.includes(s))) : f.scopes.some(s => a.scopeSet.has(s)))));
}
export function compareScopes(a, b, resource) {
  const left = new Set(a.scopes[resource] || []), right = new Set(b.scopes[resource] || []);
  return { common: [...left].filter(s => right.has(s)).sort(), left: [...left].filter(s => !right.has(s)).sort(), right: [...right].filter(s => !left.has(s)).sort() };
}
