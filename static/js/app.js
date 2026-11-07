const $ = id => document.getElementById(id);
let chart = null;
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// ---- navigation (hash based) ----
function show() {
  const v = (location.hash || '#scan').slice(1);
  const view = ['scan', 'history', 'learn'].includes(v) ? v : 'scan';
  document.querySelectorAll('.view').forEach(s => s.hidden = s.id !== 'view-' + view);
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('active', a.dataset.view === view));
  $('menu').classList.remove('open');
  if (view === 'history') loadHistory();
  if (view === 'scan') loadStats();
}
window.addEventListener('hashchange', show);
$('burger').onclick = () => $('menu').classList.toggle('open');

// ---- stats + chart ----
async function loadStats() {
  const s = await (await fetch('/api/stats')).json();
  $('sTotal').textContent = s.total; $('sSafe').textContent = s.safe; $('sBad').textContent = s.suspicious;
  if (typeof Chart === 'undefined') return;
  const data = [s.safe, s.suspicious];
  if (chart) { chart.data.datasets[0].data = data; chart.update(); return; }
  chart = new Chart($('chart'), {
    type: 'doughnut',
    data: { labels: ['Safe', 'Suspicious'], datasets: [{ data, backgroundColor: ['#34d399', '#ff5c7a'], borderColor: '#131a42' }] },
    options: { plugins: { legend: { position: 'right', labels: { color: '#e8eafc' } } }, maintainAspectRatio: false }
  });
}

// ---- scanning ----
async function scan() {
  const err = $('error'); err.hidden = true;
  const btn = $('scanBtn'); btn.disabled = true; btn.textContent = 'Scanning...';
  try {
    const res = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: $('url').value }) });
    const d = await res.json();
    if (!res.ok) { err.textContent = d.error; err.hidden = false; $('result').hidden = true; return; }
    render(d); loadStats();
  } catch (e) { err.textContent = 'Could not reach the server. Is app.py running?'; err.hidden = false; }
  finally { btn.disabled = false; btn.textContent = 'Scan Website'; }
}

function render(d) {
  const r = $('result');
  r.className = 'result ' + (d.risk === 'High' ? 'bad' : d.risk === 'Medium' ? 'mid' : 'safe');
  $('rUrl').textContent = d.url;
  $('rBadge').textContent = d.prediction;
  $('rRisk').textContent = d.risk;
  $('rConf').textContent = d.confidence + '%';
  $('rBar').style.width = '0'; requestAnimationFrame(() => $('rBar').style.width = d.confidence + '%');
  $('rExplain').textContent = d.explanation;
  $('rFeatures').innerHTML = d.contributing_features.length
    ? d.contributing_features.map(f => `<li><span>${esc(f.feature)}</span><small>model weight ${f.importance}</small></li>`).join('')
    : '<li class="ok">No warning signs found in the URL structure.</li>';
  r.hidden = false; r.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

$('scanBtn').onclick = scan;
$('url').addEventListener('keydown', e => { if (e.key === 'Enter') scan(); });
document.querySelectorAll('[data-sample]').forEach(b => b.onclick = () => { $('url').value = b.dataset.sample; scan(); });

// ---- history ----
async function loadHistory() {
  const rows = await (await fetch('/api/history')).json();
  $('histBody').innerHTML = rows.map(r => `<tr><td class="u">${esc(r.url)}</td><td>${esc(r.scanned_at)}</td>
    <td><span class="tag ${r.prediction.split(' ')[0]}">${esc(r.prediction)}</span></td>
    <td><span class="tag ${esc(r.risk)}">${esc(r.risk)}</span></td></tr>`).join('');
  $('histEmpty').hidden = rows.length > 0;
}
$('clearBtn').onclick = async () => {
  if (!confirm('Delete all scan history?')) return;
  await fetch('/api/history', { method: 'DELETE' });
  loadHistory();
};
show();
