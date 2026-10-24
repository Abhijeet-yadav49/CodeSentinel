const codeInput = document.querySelector('#code-input');
const lineNumbers = document.querySelector('#line-numbers');
const lineCount = document.querySelector('#line-count');
const analyzeButton = document.querySelector('#analyze-button');
const findingsList = document.querySelector('#findings-list');
const severityFilter = document.querySelector('#severity-filter');
const exportButton = document.querySelector('#export-json');
let latestReport = null;
let currentFilename = 'untitled.py';

const sampleCode = `import hashlib
import pickle
import subprocess

API_KEY = "sk_live_replace_me"

def run_query(user_input, filters=[]):
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    return eval(user_input)

def load_payload(data):
    return pickle.loads(data)

def run_command(command):
    return subprocess.run(command, shell=True, check=False)

def fingerprint(value):
    return hashlib.md5(value.encode()).hexdigest()

try:
    print("ready")
except:
    pass
`;

function syncLineNumbers() {
  const count = Math.max(1, codeInput.value.split('\n').length);
  lineNumbers.textContent = Array.from({length: count}, (_, i) => i + 1).join('\n');
  lineCount.textContent = `${count} line${count === 1 ? '' : 's'}`;
}
function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}
function severityClass(value) { return ['critical','high','medium','low','info'].includes(value) ? value : 'info'; }
function renderFindings() {
  if (!latestReport) return;
  const selected = severityFilter.value;
  const findings = latestReport.findings.filter(f => selected === 'all' || f.severity === selected);
  if (!findings.length) {
    findingsList.innerHTML = `<div class="empty-state"><div class="empty-icon">✓</div><h3>${latestReport.findings.length ? 'No findings at this severity' : 'No patterns detected by configured rules'}</h3><p>${latestReport.findings.length ? 'Choose another filter to review the remaining findings.' : 'This is not a guarantee that the code is secure. Static rules have limited coverage.'}</p></div>`;
    return;
  }
  findingsList.innerHTML = findings.map(f => {
    const sev = severityClass(f.severity);
    return `<article class="finding-card"><div class="finding-main"><div class="severity-rail ${sev}"></div><div class="finding-content"><div class="finding-title-row"><span class="rule-id">${escapeHTML(f.rule_id)}</span><h4>${escapeHTML(f.title)}</h4><span class="severity-label ${sev}">${escapeHTML(sev)}</span></div><p class="finding-message">${escapeHTML(f.message)}</p><div class="finding-location">Line <span>${Number(f.line)}</span>, column <span>${Number(f.column)}</span></div><pre class="code-snippet"><code>${escapeHTML(f.snippet)}</code></pre><div class="recommendation"><b>RECOMMENDATION</b><span>${escapeHTML(f.recommendation)}</span></div></div><div class="finding-side">L${Number(f.line).toString().padStart(3,'0')}</div></div></article>`;
  }).join('');
}
function updateReport(report) {
  latestReport = report;
  const summary = report.summary;
  document.querySelector('#metric-total').textContent = summary.total_findings;
  document.querySelector('#metric-critical').textContent = summary.by_severity.critical;
  document.querySelector('#metric-high').textContent = summary.by_severity.high;
  document.querySelector('#metric-lines').textContent = summary.lines_of_code;
  document.querySelector('#findings-subtitle').textContent = `${summary.total_findings} finding${summary.total_findings === 1 ? '' : 's'} · ${summary.rules_checked} rules checked · ${report.analysis_mode.replaceAll('_', ' ')}`;
  document.querySelector('#analysis-status').textContent = `Analysis complete · ${new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}`;
  document.querySelector('#disclaimer').textContent = report.disclaimer;
  exportButton.disabled = false;
  renderFindings();
}
async function analyze() {
  if (!codeInput.value.trim()) { showToast('Paste or upload Python code first.'); return; }
  analyzeButton.disabled = true;
  analyzeButton.innerHTML = '<span class="button-icon">◌</span> Analyzing…';
  document.querySelector('#analysis-status').textContent = 'Parsing source and applying rules…';
  try {
    const response = await fetch('/api/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({code:codeInput.value})});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || 'Analysis request failed.');
    updateReport(payload);
  } catch (error) {
    document.querySelector('#analysis-status').textContent = 'Analysis failed';
    showToast(error.message || 'Could not reach the analysis API.');
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.innerHTML = '<span class="button-icon">⌁</span> Analyze code <span class="button-arrow">→</span>';
  }
}
function showToast(message) {
  const old = document.querySelector('.toast'); if (old) old.remove();
  const toast = document.createElement('div'); toast.className = 'toast'; toast.textContent = message; document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2800);
}
codeInput.addEventListener('input', syncLineNumbers);
codeInput.addEventListener('scroll', () => { lineNumbers.scrollTop = codeInput.scrollTop; });
document.querySelector('#load-sample').addEventListener('click', () => {
  codeInput.value = sampleCode; currentFilename = 'sample_vulnerable.py'; document.querySelector('#filename').textContent = currentFilename; syncLineNumbers();
  document.querySelector('#analysis-status').textContent = 'Sample loaded · not yet analyzed'; showToast('Demo sample loaded. Run analysis to inspect it.');
});
document.querySelector('#file-input').addEventListener('change', async event => {
  const file = event.target.files?.[0]; if (!file) return;
  if (file.size > 200_000) { showToast('Please choose a file smaller than 200 KB.'); event.target.value = ''; return; }
  codeInput.value = await file.text(); currentFilename = file.name; document.querySelector('#filename').textContent = currentFilename; syncLineNumbers();
  document.querySelector('#analysis-status').textContent = 'File loaded · not yet analyzed'; showToast(`${file.name} loaded locally.`); event.target.value = '';
});
analyzeButton.addEventListener('click', analyze);
severityFilter.addEventListener('change', renderFindings);
exportButton.addEventListener('click', () => {
  if (!latestReport) return;
  const blob = new Blob([JSON.stringify({...latestReport, filename:currentFilename}, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${currentFilename.replace(/\.py$/i, '')}-codesentinel-report.json`; anchor.click(); URL.revokeObjectURL(url);
});
syncLineNumbers();
