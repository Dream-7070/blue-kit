function caseSolve() {
    const pathInput = document.getElementById('case-path').value.trim();
    const fileInput = document.getElementById('case-file').files[0];
    const outDiv = document.getElementById('case-out');
    const btn = document.getElementById('btn-case-solve');

    if (!pathInput && !fileInput) {
        outDiv.innerHTML = `<div class="card card-hud" style="border-color:var(--amber); color:var(--amber);">Iltimos, fayl tanlang yoki yo'l kiriting.</div>`;
        return;
    }

    btn.disabled = true;
    btn.textContent = "⏳ Yechilmoqda…";
    outDiv.innerHTML = "";

    if (fileInput) {
        const name = fileInput.name;
        if (name.endsWith('.zip')) {
            const reader = new FileReader();
            reader.onload = function(e) {
                const arr = new Uint8Array(e.target.result);
                // chunking for btoa to avoid stack overflow
                let binary = '';
                const chunkSize = 8192;
                for (let i = 0; i < arr.length; i += chunkSize) {
                    binary += String.fromCharCode.apply(null, arr.subarray(i, i + chunkSize));
                }
                const b64 = btoa(binary);
                caseSendReq({ filename: name, content_b64: b64 });
            };
            reader.onerror = function() {
                caseShowError("Faylni o'qib bo'lmadi");
            };
            reader.readAsArrayBuffer(fileInput);
        } else {
            const reader = new FileReader();
            reader.onload = function(e) {
                caseSendReq({ filename: name, content: e.target.result });
            };
            reader.onerror = function() {
                caseShowError("Faylni o'qib bo'lmadi");
            };
            reader.readAsText(fileInput);
        }
    } else {
        caseSendReq({ path: pathInput });
    }
}

function caseShowError(msg) {
    const btn = document.getElementById('btn-case-solve');
    const outDiv = document.getElementById('case-out');
    btn.disabled = false;
    btn.textContent = "🧩 Yechish";
    outDiv.innerHTML = `<div class="card card-hud" style="border-color:var(--cyber-red); color:var(--cyber-red);">${escapeHtml(msg)}</div>`;
}

async function caseSendReq(body) {
    try {
        const res = await api('/api/case/solve', 'POST', body);
        if (res.error) {
            caseShowError(res.error);
        } else {
            caseRender(res);
        }
    } catch (e) {
        caseShowError(e.toString());
    }
}

function caseCopyFlag() {
    const flagText = document.getElementById('case-flag-val').textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(flagText).then(() => {
            const t = document.getElementById('toast');
            if (t) {
                t.textContent = "✓ Flag nusxalandi!";
                t.className = "toast show";
                setTimeout(() => { t.className = t.className.replace("show", ""); }, 3000);
            }
        });
    } else {
        const ta = document.createElement('textarea');
        ta.value = flagText;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        const t = document.getElementById('toast');
        if (t) {
            t.textContent = "✓ Flag nusxalandi!";
            t.className = "toast show";
            setTimeout(() => { t.className = t.className.replace("show", ""); }, 3000);
        }
    }
}

function caseToggleAttrs(idx) {
    const tr = document.getElementById(`case-attrs-${idx}`);
    if (tr) {
        tr.style.display = (tr.style.display === 'none') ? 'table-row' : 'none';
    }
}

function caseDownloadSub(jsonStr, challengeName) {
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `submission_${challengeName}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function caseRender(res) {
    const btn = document.getElementById('btn-case-solve');
    const outDiv = document.getElementById('case-out');
    btn.disabled = false;
    btn.textContent = "🧩 Yechish";

    const c = res.counts || {};
    let wHtml = "";
    if (res.warnings && res.warnings.length > 0) {
        wHtml = `<div style="margin-top:10px; color:var(--amber);">⚠ Ogohlantirishlar:<br> ${res.warnings.map(x => escapeHtml(x)).join('<br>')}</div>`;
    }

    const flagCard = `
        <div class="card card-hud">
            <div class="card-title">
                <span>🚩 Natija: FLAG</span>
                <button class="btn btn-sm btn-primary" id="case-btn-copy">📋 Nusxa</button>
            </div>
            <h1 style="font-size:2em; font-family:monospace; margin-bottom:5px;" id="case-flag-val">${escapeHtml(res.flag || "")}</h1>
            <div class="helper-text"><code>${escapeHtml(res.flag_input || "")}</code></div>
            <div class="helper-text" style="margin-top:10px;">
                <b>Hisobot:</b> Jami: ${c.total} / Tasdiqlangan: ${c.approved} / Telemetriya: ${c.telemetry} / Nomzod: ${c.candidate} / Komponentlar: ${c.components} / Kutilgan: ${c.expected_stages || "?"}
            </div>
            ${wHtml}
        </div>
    `;

    let chainRows = "";
    let attrRows = "";
    (res.chain || []).forEach((e, idx) => {
        let outColor = "var(--text-main)";
        if (e.outcome === "success") outColor = "var(--cyber-red)";
        else if (e.outcome === "blocked") outColor = "var(--amber)";
        else if (e.outcome === "response") outColor = "var(--cyber-mint)";

        let warnStr = e.order_uncertain ? " <span style='color:var(--amber)'>⚠ tartib noaniq</span>" : "";
        let linksStr = (e.links || []).map(l => escapeHtml(l.stage + '-bosqich: ' + l.values.join(', '))).join('<br>');
        
        let outHtml = `<span style="color:${outColor}">${escapeHtml(e.outcome || "")}</span>`;

        chainRows += `
            <tr style="cursor:pointer;" data-idx="${idx}" class="case-chain-row">
                <td>${idx + 1}</td>
                <td>${escapeHtml(e.utc || "")}</td>
                <td>${escapeHtml(e.raw_time || "")} (${e.off > 0 ? '+' : ''}${e.off})</td>
                <td>${escapeHtml(e.source || "")}</td>
                <td>${escapeHtml(e.action || "")}</td>
                <td>${escapeHtml(e.id || "")}</td>
                <td>${outHtml}${warnStr}</td>
                <td style="font-size:0.85em;">${linksStr}</td>
            </tr>
        `;

        let aHtml = Object.entries(e.attrs || {}).map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`).join('');
        attrRows += `
            <tr id="case-attrs-${idx}" style="display:none; background:var(--bg-main);">
                <td colspan="8">
                    <div style="padding:10px;">
                        <table class="data-table" style="width:100%;">
                            <thead><tr><th>Atribut</th><th>Qiymat</th></tr></thead>
                            <tbody>${aHtml}</tbody>
                        </table>
                    </div>
                </td>
            </tr>
        `;
    });

    const chainCard = `
        <div class="card card-hud" style="margin-top:20px;">
            <div class="card-title"><span>⚡ Zanjir (${(res.chain || []).length} ta hodisa)</span></div>
            <div class="table-responsive">
                <table class="data-table" id="case-chain-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>UTC</th>
                            <th>Manba vaqti (offset)</th>
                            <th>Manba</th>
                            <th>Action</th>
                            <th>Event ID</th>
                            <th>Natija</th>
                            <th>Bog'lanish</th>
                        </tr>
                    </thead>
                    <tbody id="case-chain-tbody">
                    </tbody>
                </table>
            </div>
        </div>
    `;

    let laHtml = "";
    (res.lookalike_groups || []).forEach(g => {
        let netHtml = (g.networks || []).map(n => `${escapeHtml(n.ip)} (${n.in_approved_network ? '✓' : '✗'})`).join(', ');
        laHtml += `
            <div style="margin-bottom:10px; padding:10px; border:1px solid var(--border-card); border-radius:4px;">
                <b>Ticket:</b> ${escapeHtml(g.ticket || "")} | <b>Actor:</b> ${escapeHtml(g.actor_class || "")} | <b>Soni:</b> ${g.events} | <b>Sabab:</b> ${escapeHtml(g.reason || "")}<br>
                <b>Actions:</b> ${escapeHtml((g.actions || []).join(', '))}<br>
                <b>IP lar:</b> ${netHtml}
            </div>
        `;
    });
    const laCard = laHtml ? `
        <div class="card card-hud" style="margin-top:20px;">
            <div class="card-title"><span>👥 Lookalike'lar (benign_exclusions)</span></div>
            ${laHtml}
        </div>
    ` : "";

    let detHtml = "";
    ((res.submission || {}).detections || []).forEach(d => {
        detHtml += `
            <div style="margin-bottom:10px; padding:10px; border:1px solid var(--border-card); border-radius:4px;">
                <b>Name:</b> ${escapeHtml(d.name || "")}<br>
                <b>Logic:</b> <code>${escapeHtml(d.logic || "")}</code><br>
                <b>FP Control:</b> ${escapeHtml(d.false_positive_control || "")}<br>
                <b>Misol:</b> ${escapeHtml(d.example_event_id || "")}
            </div>
        `;
    });
    const detCard = detHtml ? `
        <div class="card card-hud" style="margin-top:20px;">
            <div class="card-title"><span>🛡 Detection'lar</span></div>
            ${detHtml}
        </div>
    ` : "";

    let orphHtml = "";
    (res.orphans || []).forEach(e => {
        orphHtml += `<li>${escapeHtml(e.id || "")} (${escapeHtml(e.source || "")} - ${escapeHtml(e.action || "")})</li>`;
    });
    const orphCard = orphHtml ? `
        <div class="card card-hud" style="margin-top:20px;">
            <div class="card-title"><span>❓ Orphans / Unknowns</span></div>
            <ul>${orphHtml}</ul>
        </div>
    ` : "";

    const subJson = JSON.stringify(res.submission || {}, null, 2);
    const fnameExt = document.getElementById('case-file').files[0] ? document.getElementById('case-file').files[0].name.replace('.json','').replace('.zip','') : 'out';
    const subCard = `
        <div class="card card-hud" style="margin-top:20px;">
            <div class="card-title">
                <span>📑 Submission</span>
                <button class="btn btn-sm btn-primary" id="case-btn-dl" data-fname="${escapeHtml(fnameExt)}">⬇ submission.json yuklab olish</button>
            </div>
            <details>
                <summary style="cursor:pointer; padding:5px 0;"><b>JSON ni ko'rish</b></summary>
                <pre style="background:var(--bg-main); padding:10px; border-radius:4px; max-height:400px; overflow-y:auto;" id="case-sub-pre"></pre>
            </details>
        </div>
    `;

    outDiv.innerHTML = flagCard + chainCard + laCard + detCard + orphCard + subCard;
    
    // Add chain rows efficiently
    const tbody = document.getElementById('case-chain-tbody');
    if (tbody) {
        // Interleave main rows and their attr rows
        let rowsHtml = "";
        (res.chain || []).forEach((e, idx) => {
            let outColor = "var(--text-main)";
            if (e.outcome === "success") outColor = "var(--cyber-red)";
            else if (e.outcome === "blocked") outColor = "var(--amber)";
            else if (e.outcome === "response") outColor = "var(--cyber-mint)";

            let warnStr = e.order_uncertain ? " <span style='color:var(--amber)'>⚠ tartib noaniq</span>" : "";
            let linksStr = (e.links || []).map(l => escapeHtml(l.stage + '-bosqich: ' + l.values.join(', '))).join('<br>');
            let outHtml = `<span style="color:${outColor}">${escapeHtml(e.outcome || "")}</span>`;

            rowsHtml += `
                <tr style="cursor:pointer;" data-idx="${idx}" class="case-chain-row">
                    <td>${idx + 1}</td>
                    <td>${escapeHtml(e.utc || "")}</td>
                    <td>${escapeHtml(e.raw_time || "")} (${e.off > 0 ? '+' : ''}${e.off})</td>
                    <td>${escapeHtml(e.source || "")}</td>
                    <td>${escapeHtml(e.action || "")}</td>
                    <td>${escapeHtml(e.id || "")}</td>
                    <td>${outHtml}${warnStr}</td>
                    <td style="font-size:0.85em;">${linksStr}</td>
                </tr>
            `;

            let aHtml = Object.entries(e.attrs || {}).map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`).join('');
            rowsHtml += `
                <tr id="case-attrs-${idx}" style="display:none; background:var(--bg-main);">
                    <td colspan="8">
                        <div style="padding:10px;">
                            <table class="data-table" style="width:100%;">
                                <thead><tr><th>Atribut</th><th>Qiymat</th></tr></thead>
                                <tbody>${aHtml}</tbody>
                            </table>
                        </div>
                    </td>
                </tr>
            `;
        });
        tbody.innerHTML = rowsHtml;
    }

    // Attach event listeners
    const copyBtn = document.getElementById('case-btn-copy');
    if (copyBtn) copyBtn.addEventListener('click', caseCopyFlag);

    const dlBtn = document.getElementById('case-btn-dl');
    if (dlBtn) dlBtn.addEventListener('click', function() {
        caseDownloadSub(subJson, this.getAttribute('data-fname'));
    });
    
    const pre = document.getElementById('case-sub-pre');
    if (pre) pre.textContent = subJson; // Safe injection

    const chainRowsEls = document.querySelectorAll('.case-chain-row');
    chainRowsEls.forEach(r => {
        r.addEventListener('click', function() {
            caseToggleAttrs(this.getAttribute('data-idx'));
        });
    });
}
