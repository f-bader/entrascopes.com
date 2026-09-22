import { booleanFilters, emptyFilters, readState, stateQuery, makeCatalog, filterApps, compareScopes } from './app-data.mjs';

const $ = id => document.getElementById(id);
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const number = value => value.toLocaleString('en-US');
const badge = (text, tone = '') => `<span class="badge ${tone}">${escape(text)}</span>`;
const external = (url, text) => { try { if (!['http:', 'https:'].includes(new URL(url).protocol)) return ''; } catch { return ''; } return `<a href="${escape(url)}" target="_blank" rel="noopener noreferrer">${escape(text)} ↗</a>`; };
let { filters, view, compare } = readState(location.search);
let catalog, matches = [], page = 1, pageSize = 25, sort = 'name', direction = 1, detailTab = 'scopes', timer, searchTimer;
let returnFocus = null;
const detailDialog = $('app-dialog'), compareDialog = $('compare-dialog');
const wideDetails = matchMedia('(min-width: 1200px)');
const filterNames = { foci: 'FOCI', clientType: 'Client', naa: 'Broker', bypass: 'CA bypass', authcodeFix: 'AuthCodeFix' };

function announce(message) {
  const modal = document.querySelector('dialog[open]');
  let target = modal?.querySelector('[data-toast]') || $('toast');
  if (modal && target === $('toast')) {
    target = document.createElement('div');
    target.className = 'toast';
    target.dataset.toast = '';
    target.setAttribute('role', 'status');
    target.setAttribute('aria-live', 'polite');
    modal.appendChild(target);
  }
  document.querySelectorAll('.toast').forEach(item => { item.textContent = ''; });
  target.textContent = message;
  clearTimeout(timer);
  timer = setTimeout(() => { target.textContent = ''; }, 3500);
}
async function copy(text, label = 'Copied to clipboard') {
  try { await navigator.clipboard.writeText(text); announce(label); }
  catch { announce('Clipboard unavailable. Select the text and copy it manually.'); }
}
function updateUrl(mode = 'push') {
  const next = location.pathname + stateQuery(filters, view, compare);
  if (next !== location.pathname + location.search) history[mode === 'replace' ? 'replaceState' : 'pushState']({}, '', next);
}
function resourceName(id) { return catalog.resourceNames.get(id) || id; }
function chip(kind, value, label) {
  return `<button class="chip" data-remove="${kind}" data-value="${escape(value)}" aria-label="Remove ${escape(label)} filter" title="${escape(label)}"><span>${escape(label)}</span><span aria-hidden="true">×</span></button>`;
}
function syncFilters() {
  $('search').value = filters.search;
  for (const key of booleanFilters) {
    $(key).value = filters[key];
    if (filters[key]) $(key).closest('details').open = true;
  }
  for (const [kind, singular] of [['apps', 'app'], ['resources', 'resource'], ['scopes', 'scope']]) {
    const label = value => kind === 'apps' ? catalog.byId.get(value)?.name || value : kind === 'resources' ? resourceName(value) : value;
    $(`${singular}-chips`).innerHTML = filters[kind].map(value => chip(kind, value, label(value))).join('');
    if (filters[kind].length) $(`${singular}-input`).closest('details').open = true;
  }
  let active = filters.search ? chip('search', filters.search, `Search: ${filters.search}`) : '';
  for (const key of booleanFilters) if (filters[key]) active += chip(key, filters[key], `${filterNames[key]}: ${$(key).selectedOptions[0].textContent}`);
  for (const kind of ['apps', 'resources', 'scopes']) {
    for (const value of filters[kind]) active += chip(kind, value, kind === 'apps' ? catalog.byId.get(value)?.name || value : kind === 'resources' ? resourceName(value) : value);
  }
  $('active-filters').innerHTML = active;
  $('filter-count').textContent = booleanFilters.filter(key => filters[key]).length + filters.apps.length + filters.resources.length + filters.scopes.length + Number(Boolean(filters.search));
}
function applyFilters(mode = 'push') {
  if (!catalog) return;
  clearTimeout(searchTimer);
  page = 1;
  updateUrl(mode);
  syncFilters();
  renderResults();
}
function resetFilters() {
  filters = emptyFilters();
  document.querySelectorAll('.add-filter input').forEach(input => { input.value = ''; });
  applyFilters();
}
function appBadges(app) {
  return `${app.foci ? badge('FOCI', 'green') : ''}${app.hasNaa ? badge('BroCI', 'blue') : ''}`;
}
function findingBadges(app) {
  return `${app.activeBypasses.length ? badge('CA bypass', 'amber') : ''}${app.authcodeFix.length ? badge('AuthCodeFix', 'red') : ''}${!app.activeBypasses.length && app.bypasses.length ? badge('Mitigated') : ''}` || '<span class="muted" title="No findings listed">—</span>';
}
function renderResults() {
  matches = filterApps(catalog.apps, filters).sort((a, b) => direction * (sort === 'name' ? a.name.localeCompare(b.name) : sort === 'resources' ? a.resourceIds.length - b.resourceIds.length : a.scopeCount - b.scopeCount));
  const totalPages = Math.max(1, Math.ceil(matches.length / pageSize));
  page = Math.min(page, totalPages);
  const start = (page - 1) * pageSize;
  $('app-rows').innerHTML = matches.slice(start, start + pageSize).map(app => `<tr>
    <td><input type="checkbox" data-compare="${escape(app.id)}" aria-label="Compare ${escape(app.name)}" ${compare.includes(app.id) ? 'checked' : ''} ${compare.length === 2 && !compare.includes(app.id) ? 'disabled' : ''}></td>
    <td><a class="app-name" data-open="${escape(app.id)}" href="${escape(stateQuery(filters, app.id, compare))}">${escape(app.name)}</a><div class="app-id"><code>${escape(app.id)}</code><button class="copy-button" data-copy="${escape(app.id)}" aria-label="Copy ${escape(app.name)} application ID" title="Copy application ID">⧉</button></div></td>
    <td><span class="client-type">${app.public_client ? 'Public' : 'Confidential'}</span><div class="badges">${appBadges(app)}</div></td>
    <td class="numeric">${number(app.resourceIds.length)}</td><td class="numeric">${number(app.scopeCount)}</td>
    <td><div class="badges">${findingBadges(app)}</div></td><td><a class="open-arrow" data-open="${escape(app.id)}" href="${escape(stateQuery(filters, app.id, compare))}" aria-label="Open ${escape(app.name)} details">↗</a></td>
  </tr>`).join('');
  $('result-count').textContent = number(matches.length);
  $('results-status').textContent = matches.length === catalog.apps.length ? 'All applications' : `${number(matches.length)} of ${number(catalog.apps.length)} applications`;
  $('empty').hidden = matches.length > 0;
  $('page-description').textContent = matches.length ? `Showing ${number(start + 1)}–${number(Math.min(start + pageSize, matches.length))} of ${number(matches.length)} applications` : 'No applications to display';
  $('page-number').textContent = `${page} / ${totalPages}`;
  $('previous').disabled = page === 1;
  $('next').disabled = page === totalPages;
  document.querySelectorAll('[data-sort]').forEach(button => {
    const name = button.dataset.sort;
    button.innerHTML = `${name === 'name' ? 'Application' : name === 'resources' ? 'Resources' : 'Scopes'}${sort === name ? `<span aria-hidden="true">${direction === 1 ? '↓' : '↑'}</span>` : ''}`;
    button.closest('th').setAttribute('aria-sort', sort === name ? direction === 1 ? 'ascending' : 'descending' : 'none');
  });
  renderTray();
}
function renderTray() {
  $('compare-tray').hidden = compare.length === 0;
  $('open-compare').disabled = compare.length !== 2;
  $('compare-selection').innerHTML = compare.map(id => `<button data-uncompare="${escape(id)}" aria-label="Remove ${escape(catalog.byId.get(id).name)} from comparison">${escape(catalog.byId.get(id).name)} <span aria-hidden="true">×</span></button>`).join('') + (compare.length === 1 ? '<span class="muted">Select one more application</span>' : '');
}
function toggleComparison(id) {
  if (compare.includes(id)) compare = compare.filter(value => value !== id);
  else if (compare.length < 2 && catalog.byId.has(id)) compare.push(id);
  updateUrl();
  renderResults();
}
function openDetail(id, push = true) {
  const app = catalog.byId.get(id);
  if (!app) { announce('This application is not in the current dataset.'); return; }
  if (!detailDialog.open) returnFocus = document.activeElement;
  view = id;
  detailTab = 'scopes';
  $('detail-search').value = '';
  if (push) updateUrl();
  $('detail-header').innerHTML = `<h2 id="detail-title">${escape(app.name)}</h2><div class="detail-id"><code>${escape(app.id)}</code><button class="copy-button" data-copy="${escape(app.id)}" aria-label="Copy application ID">⧉</button></div><div class="detail-badges">${badge(app.public_client ? 'Public client' : 'Confidential client')}${appBadges(app)}${findingBadges(app)}</div><div class="detail-metrics"><div><strong>${number(app.resourceIds.length)}</strong><span>Resources</span></div><div><strong>${number(app.scopeCount)}</strong><span>Scopes</span></div><div><strong>${number(app.redirect_uris.length)}</strong><span>Redirect URIs</span></div></div>`;
  renderDetail();
  if (!detailDialog.open) detailDialog.showModal();
  detailDialog.scrollTop = 0;
  $('close-detail').focus();
}
function closeDetail(push = true) {
  detailDialog.close();
  view = '';
  if (push) updateUrl();
  if (returnFocus?.isConnected) returnFocus.focus();
}
function tierBadge(resource, scope) {
  const tier = catalog.tiers.get(`${resource}:${scope}`);
  return tier ? external('https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model', `EAM: ${tier}`).replace('<a ', `<a class="badge ${tier === 'ControlPlane' ? 'red' : tier === 'ManagementPlane' ? 'amber' : 'green'}" `) : '';
}
function renderDetail() {
  const app = catalog.byId.get(view);
  if (!app) return;
  document.querySelectorAll('[data-tab]').forEach(button => button.setAttribute('aria-current', button.dataset.tab === detailTab ? 'page' : 'false'));
  const q = $('detail-search').value.trim().toLowerCase();
  $('detail-search').placeholder = wideDetails.matches ? 'Filter scopes, redirect URIs, or findings…' : detailTab === 'scopes' ? 'Filter resources or scopes…' : detailTab === 'redirects' ? 'Filter redirect URIs…' : 'Filter findings…';
  const sections = [['scopes', 'Scopes & resources'], ['redirects', 'Redirect URIs'], ['findings', 'Findings']];
  $('detail-content').innerHTML = wideDetails.matches
    ? sections.map(([section, title]) => `<section class="detail-section" aria-labelledby="section-${section}"><h3 id="section-${section}">${title}</h3><div class="detail-section-body" tabindex="0" role="region" aria-label="${title}">${renderDetailSection(app, section, q)}</div></section>`).join('')
    : renderDetailSection(app, detailTab, q);
}
function renderDetailSection(app, section, q) {
  let content = '';
  if (section === 'scopes') {
    content = app.resourceEntries.map(([id, scopes], index) => {
      const resourceMatches = `${resourceName(id)} ${id}`.toLowerCase().includes(q);
      const filtered = resourceMatches ? scopes : scopes.filter(s => s.toLowerCase().includes(q));
      if (!filtered.length && !resourceMatches) return '';
      return `<details class="resource-group" ${q || app.resourceEntries.length === 1 || wideDetails.matches && index === 0 ? 'open' : ''}><summary><span class="count">${filtered.length} ${filtered.length === 1 ? 'scope' : 'scopes'}</span>${escape(resourceName(id))}<code>${escape(id)}</code></summary><ul class="scope-list">${[...filtered].sort().map(scope => `<li><code>${escape(scope)}</code>${tierBadge(id, scope)}</li>`).join('')}</ul></details>`;
    }).join('');
  } else if (section === 'redirects') {
    const preferred = [['Preferred interactive redirect', app.preferred_interactive_redirurl], ['Preferred non-interactive redirect', app.preferred_noninteractive_redirurl]];
    content = preferred.filter(([, uri]) => !q || uri?.toLowerCase().includes(q)).map(([label, uri]) => `<div class="uri-card"><h3>${label}</h3><code>${escape(uri || 'None specified')}</code></div>`).join('');
    content += app.redirect_uris.filter(uri => uri.toLowerCase().includes(q)).map(uri => {
      const broker = uri.match(/^brk-([0-9a-f-]{36})/i)?.[1];
      const brokerApp = catalog.byId.get(broker?.toLowerCase());
      return `<div class="uri-card">${broker ? '<h3>Broker / nested app authentication</h3>' : ''}<code>${escape(uri)}</code>${brokerApp ? `<a data-open="${escape(brokerApp.id)}" href="${escape(stateQuery(filters, brokerApp.id, compare))}">Brokered by ${escape(brokerApp.name)} ↗</a>` : broker ? '<p class="section-note">Broker application not found in this dataset.</p>' : ''}</div>`;
    }).join('');
  } else {
    content = '';
    const bypasses = app.bypasses.filter(b => `${b.Description} ${b.CurrentState} ${b.ProtectionBypass?.join(' ')}`.toLowerCase().includes(q));
    content += bypasses.map(b => `<article class="finding-card"><h3>Conditional Access bypass</h3>${badge(b.CurrentState, /^mitigated$/i.test(b.CurrentState) ? 'green' : 'amber')}${(b.ProtectionBypass || []).map(p => badge(p)).join('')}<p>${escape(b.Description)}</p><ul>${(b.ResourcesAndScopes || []).flatMap(rs => Object.entries(rs).map(([r, scopes]) => `<li>${escape(resourceName(r))}: ${scopes.map(escape).join(', ')}</li>`)).join('')}</ul>${(b.ReadMore || []).map((link, i) => external(link, `Source ${i + 1}`)).join('')}${(b.Attribution || []).map(link => external(link, 'Attribution')).join('')}</article>`).join('');
    const fixes = app.authcodeFix.filter(f => `${f.AffectedReferer} ${f.Reason}`.toLowerCase().includes(q));
    content += fixes.map(f => `<article class="finding-card"><h3>AuthCodeFix / ConsentFix indicator</h3>${badge(f.Reason, 'red')}<p><code>${escape(f.AffectedReferer)}</code></p></article>`).join('');
    if (!bypasses.length && !fixes.length) content += '<p class="section-note">No matching findings listed.</p>';
  }
  return content || '<p class="section-note">No matching entries.</p>';
}
wideDetails.addEventListener('change', () => { if (detailDialog.open) renderDetail(); });
function openComparison() {
  if (compare.length !== 2) return;
  const [a, b] = compare.map(id => catalog.byId.get(id));
  const common = a.resourceIds.filter(id => b.resourceIds.includes(id)).length;
  $('comparison-content').innerHTML = `<div class="compare-summary">${[a, b].map((app, i) => `<div><span class="eyebrow">APPLICATION ${i + 1}</span><h3>${escape(app.name)}</h3><code>${escape(app.id)}</code><p>${number(app.resourceIds.length)} resources · ${number(app.scopeCount)} scopes · ${app.public_client ? 'Public' : 'Confidential'} client</p><div class="badges">${appBadges(app)}${findingBadges(app)}</div></div>`).join('')}</div><p class="section-note">${common} shared resources · ${a.resourceIds.length - common} unique to application 1 · ${b.resourceIds.length - common} unique to application 2</p><div class="compare-controls"><label class="sr-only" for="compare-search">Search comparison</label><input type="search" id="compare-search" placeholder="Filter resources or scopes…"><label><input id="differences-only" type="checkbox">Only differences</label></div><div id="comparison-resources"></div>`;
  $('compare-search').addEventListener('input', renderComparisonResources);
  $('differences-only').addEventListener('change', renderComparisonResources);
  renderComparisonResources();
  compareDialog.showModal();
  $('close-compare').focus();
}
function renderComparisonResources() {
  const [a, b] = compare.map(id => catalog.byId.get(id)), q = $('compare-search').value.trim().toLowerCase();
  const onlyDifferences = $('differences-only').checked;
  const resources = [...new Set([...a.resourceIds, ...b.resourceIds])].sort((a, b) => resourceName(a).localeCompare(resourceName(b)));
  $('comparison-resources').innerHTML = resources.map(id => {
    const diff = compareScopes(a, b, id);
    if (onlyDifferences && !diff.left.length && !diff.right.length) return '';
    const resourceMatches = `${resourceName(id)} ${id}`.toLowerCase().includes(q);
    if (!resourceMatches && ![...diff.left, ...diff.right, ...diff.common].some(s => s.toLowerCase().includes(q))) return '';
    const columns = [['Only application 1', diff.left], ['Shared scopes', diff.common], ['Only application 2', diff.right]];
    return `<details class="resource-group" ${q ? 'open' : ''}><summary>${escape(resourceName(id))}<code>${escape(id)} · ${diff.common.length} shared / ${diff.left.length + diff.right.length} different</code></summary><div class="scope-diff">${columns.map(([label, scopes]) => `<div><h3>${label} (${scopes.length})</h3>${scopes.filter(s => resourceMatches || s.toLowerCase().includes(q)).map(s => `<code>${escape(s)}</code>`).join('') || '<span class="muted">—</span>'}</div>`).join('')}</div></details>`;
  }).join('') || '<p class="section-note">No matching resources.</p>';
}

async function load() {
  $('load-error').hidden = true;
  $('table-wrap').hidden = false;
  $('table-wrap').setAttribute('aria-busy', 'true');
  $('results-status').textContent = 'Loading application data…';
  try {
    const files = ['firstpartyscopes.json', 'resources.json', 'bypasses.json', 'Classification_AppRoles.json', 'authcodefix.json'];
    const datasets = await Promise.all(files.map(async file => {
      const response = await fetch(file);
      if (!response.ok) throw new Error(`Could not load ${file} (HTTP ${response.status}).`);
      return response.json();
    }));
    catalog = makeCatalog(...datasets);
    compare = compare.filter(id => catalog.byId.has(id));
    $('stat-apps').textContent = number(catalog.apps.length);
    $('stat-resources').textContent = number(catalog.resources.length);
    $('stat-scopes').textContent = number(catalog.scopes.length);
    $('resource-options').innerHTML = catalog.resources.map(id => `<option value="${escape(resourceName(id))} (${escape(id)})"></option>`).join('');
    $('scope-options').innerHTML = catalog.scopes.map(scope => `<option value="${escape(scope)}"></option>`).join('');
    $('app-options').innerHTML = catalog.apps.map(a => `<option value="${escape(a.name)} (${escape(a.id)})"></option>`).join('');
    syncFilters(); renderResults();
    if (view) openDetail(view, false);
    $('table-wrap').setAttribute('aria-busy', 'false');
  } catch (error) {
    $('table-wrap').hidden = true;
    $('load-error').hidden = false;
    $('error-message').textContent = location.protocol === 'file:' ? 'Open this site through the local preview server to load its JSON datasets.' : error.message;
    $('results-status').textContent = 'Data unavailable. Please try again.';
    $('page-description').textContent = 'Dataset not loaded';
  }
}

$('search').addEventListener('input', () => {
  filters.search = $('search').value;
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => applyFilters('replace'), 140);
});
for (const key of booleanFilters) $(key).addEventListener('change', () => { filters[key] = $(key).value; applyFilters(); });
document.querySelectorAll('.add-filter').forEach(form => form.addEventListener('submit', event => {
  event.preventDefault();
  if (!catalog) return;
  const input = form.querySelector('input'), kind = form.dataset.kind, raw = input.value.trim();
  if (!raw) return;
  let value = raw;
  if (kind !== 'scopes') {
    value = raw.match(/\(([0-9a-f-]{36})\)$/i)?.[1] || raw;
    if (kind === 'resources' && !catalog.resources.includes(value)) value = catalog.resources.find(id => resourceName(id).toLowerCase() === raw.toLowerCase()) || value;
    if (kind === 'apps' && !catalog.byId.has(value)) value = catalog.apps.find(a => a.name.toLowerCase() === raw.toLowerCase())?.id || value;
  }
  const valid = kind === 'apps' ? catalog.byId.has(value) : kind === 'resources' ? catalog.resources.includes(value) : catalog.scopes.includes(value);
  if (!valid) { announce('Choose an exact value from the suggestions.'); input.focus(); return; }
  if (!filters[kind].includes(value)) filters[kind].push(value);
  input.value = ''; applyFilters(); input.focus();
}));
document.addEventListener('click', event => {
  const copyButton = event.target.closest('[data-copy]');
  if (copyButton) { copy(copyButton.dataset.copy, 'Application ID copied'); return; }
  const link = event.target.closest('[data-open]');
  if (link && !event.metaKey && !event.ctrlKey && !event.shiftKey && event.button === 0) { event.preventDefault(); openDetail(link.dataset.open); return; }
  const remove = event.target.closest('[data-remove]');
  if (remove) {
    const key = remove.dataset.remove;
    if (Array.isArray(filters[key])) filters[key] = filters[key].filter(value => value !== remove.dataset.value);
    else filters[key] = '';
    applyFilters(); $('search').focus(); return;
  }
  const uncompare = event.target.closest('[data-uncompare]');
  if (uncompare) { toggleComparison(uncompare.dataset.uncompare); return; }
  const sortButton = event.target.closest('[data-sort]');
  if (sortButton && catalog) { const next = sortButton.dataset.sort; direction = sort === next ? -direction : next === 'name' ? 1 : -1; sort = next; page = 1; renderResults(); }
});
$('app-rows').addEventListener('change', event => {
  if (event.target.matches('[data-compare]')) {
    const id = event.target.dataset.compare;
    toggleComparison(id);
    document.querySelector(`[data-compare="${CSS.escape(id)}"]`)?.focus();
    announce(`${compare.length} of 2 applications selected`);
  }
});
$('reset').addEventListener('click', resetFilters);
$('empty-reset').addEventListener('click', resetFilters);
$('retry').addEventListener('click', load);
$('share').addEventListener('click', () => copy(`${location.origin}${location.pathname}${stateQuery(filters, view, compare)}`, 'Explorer link copied'));
$('page-size').addEventListener('change', () => { pageSize = Number($('page-size').value); page = 1; if (catalog) renderResults(); });
for (const [id, change] of [['previous', -1], ['next', 1]]) $(id).addEventListener('click', () => { page += change; renderResults(); $('results').scrollIntoView({ block: 'start' }); });
$('clear-compare').addEventListener('click', () => { compare = []; updateUrl(); renderResults(); });
$('open-compare').addEventListener('click', openComparison);
$('close-compare').addEventListener('click', () => compareDialog.close());
$('close-detail').addEventListener('click', () => closeDetail());
detailDialog.addEventListener('cancel', event => { event.preventDefault(); closeDetail(); });
for (const dialog of [detailDialog, compareDialog]) dialog.addEventListener('click', event => {
  if (event.target !== dialog) return;
  const rect = dialog.getBoundingClientRect();
  if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) dialog === detailDialog ? closeDetail() : dialog.close();
});
document.querySelectorAll('[data-tab]').forEach(button => button.addEventListener('click', () => { detailTab = button.dataset.tab; $('detail-search').value = ''; renderDetail(); }));
$('detail-search').addEventListener('input', renderDetail);
document.addEventListener('keydown', event => {
  if (event.key === '/' && !event.ctrlKey && !event.metaKey && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName) && !detailDialog.open && !compareDialog.open) { event.preventDefault(); $('search').focus(); }
});
window.addEventListener('popstate', () => {
  clearTimeout(searchTimer);
  ({ filters, view, compare } = readState(location.search));
  if (!catalog) return;
  compare = compare.filter(id => catalog.byId.has(id));
  page = 1;
  compareDialog.close();
  syncFilters(); renderResults();
  if (view && catalog.byId.has(view)) openDetail(view, false);
  else if (detailDialog.open) closeDetail(false);
});
if (matchMedia('(max-width: 850px)').matches) document.querySelectorAll('.filter-disclosure').forEach(details => { details.open = false; });
load();
