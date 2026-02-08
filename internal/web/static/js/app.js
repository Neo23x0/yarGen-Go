const API_BASE = '';
let currentJobId = null;
let uploadedFiles = [];
let allRules = [];
let allTags = [];
let selectedTags = [];

document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    setupDropzone();
    setupGenerate();
    setupRulesPage();
    setupRuleNaming();
    setupSettingsPage();
    loadConfig();
    loadTags();
});

function setupNavigation() {
    document.querySelectorAll('nav a').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const pageId = link.id.replace('nav-', 'page-');
            document.querySelectorAll('nav a').forEach(l => l.classList.remove('active'));
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            link.classList.add('active');
            document.getElementById(pageId).classList.add('active');
            if (pageId === 'page-rules') loadRules();
        });
    });
}

function setupDropzone() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const fileList = document.getElementById('file-list');
    const clearBtn = document.getElementById('clear-files');

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(event => {
        dropZone.addEventListener(event, e => { e.preventDefault(); e.stopPropagation(); });
    });

    ['dragenter', 'dragover'].forEach(event => {
        dropZone.addEventListener(event, () => dropZone.classList.add('drag-over'));
    });

    ['dragleave', 'drop'].forEach(event => {
        dropZone.addEventListener(event, () => dropZone.classList.remove('drag-over'));
    });

    dropZone.addEventListener('drop', e => handleFiles(e.dataTransfer.files));
    fileInput.addEventListener('change', e => handleFiles(e.target.files));

    clearBtn.addEventListener('click', () => {
        uploadedFiles = [];
        currentJobId = null;
        updateFileList();
        document.getElementById('generate-btn').disabled = true;
        clearBtn.style.display = 'none';
    });
}

function handleFiles(files) {
    const formData = new FormData();
    for (const file of files) {
        formData.append('files', file);
        uploadedFiles.push({ name: file.name, size: file.size });
    }

    fetch(`${API_BASE}/api/upload`, { method: 'POST', body: formData })
        .then(r => r.json())
        .then(job => {
            currentJobId = job.id;
            uploadedFiles = job.files;
            updateFileList();
            document.getElementById('generate-btn').disabled = false;
            document.getElementById('clear-files').style.display = 'inline-block';
        })
        .catch(err => showStatus('Upload failed: ' + err.message, true));
}

function updateFileList() {
    const list = document.getElementById('file-list');
    list.innerHTML = uploadedFiles.map(f => `
        <div class="file-item">
            <span class="name">${f.name}</span>
            <span class="size">${formatSize(f.size)}</span>
        </div>
    `).join('');
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function setupGenerate() {
    document.getElementById('generate-btn').addEventListener('click', generateRules);
    document.getElementById('copy-btn').addEventListener('click', () => {
        navigator.clipboard.writeText(document.getElementById('rules-output').textContent);
    });
    document.getElementById('download-btn').addEventListener('click', downloadRules);
}

function generateRules() {
    if (!currentJobId) return;

    const opts = {
        job_id: currentJobId,
        author: document.getElementById('opt-author').value,
        reference: document.getElementById('opt-reference').value,
        show_scores: document.getElementById('opt-scores').checked,
        exclude_opcodes: document.getElementById('opt-no-opcodes').checked,
        no_super: document.getElementById('opt-no-super').checked,
        exclude_goodware: document.getElementById('opt-exclude-good').checked,
        no_magic: document.getElementById('opt-no-magic').checked,
        no_filesize: document.getElementById('opt-no-filesize').checked,
        filesize_multiplier: parseInt(document.getElementById('opt-fs-mult').value) || 3,
        use_llm: document.getElementById('opt-llm').checked,
        min_score: parseFloat(document.getElementById('opt-min-score').value) || 0,
        max_strings: parseInt(document.getElementById('opt-max-strings').value) || 20,
        debug: document.getElementById('opt-debug').checked
    };

    showStatus('Generating rules...', false);
    document.getElementById('generate-btn').disabled = true;

    fetch(`${API_BASE}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(opts)
    })
    .then(r => r.json())
    .then(() => pollJobStatus())
    .catch(err => {
        showStatus('Generation failed: ' + err.message, true);
        document.getElementById('generate-btn').disabled = false;
    });
}

function pollJobStatus() {
    const poll = () => {
        fetch(`${API_BASE}/api/jobs/${currentJobId}`)
            .then(r => r.json())
            .then(job => {
                if (job.status === 'completed') {
                    showRules(job.rules, job.debug_log);
                    hideStatus();
                    document.getElementById('generate-btn').disabled = false;
                    notifyCompletion('YARA rules generated successfully');
                } else if (job.status === 'error') {
                    showStatus('Error: ' + job.error, true);
                    document.getElementById('generate-btn').disabled = false;
                } else {
                    setTimeout(poll, 1000);
                }
            });
    };
    poll();
}

function showRules(rules, debugLog) {
    document.getElementById('rules-output').textContent = rules;
    document.getElementById('output-section').style.display = 'block';
    
    const debugSection = document.getElementById('debug-section');
    const debugOutput = document.getElementById('debug-output');
    if (debugLog && debugLog.trim()) {
        debugOutput.textContent = debugLog;
        debugSection.style.display = 'block';
    } else {
        debugSection.style.display = 'none';
    }
}

function downloadRules() {
    if (!currentJobId) return;
    window.location.href = `${API_BASE}/api/jobs/${currentJobId}/rules`;
}

function showStatus(message, isError) {
    const section = document.getElementById('status-section');
    const msg = document.getElementById('status-message');
    section.style.display = 'block';
    msg.textContent = message;
    msg.style.color = isError ? '#f87171' : '#fff';
}

function hideStatus() {
    document.getElementById('status-section').style.display = 'none';
}

function setupRulesPage() {
    document.getElementById('add-rule-btn').addEventListener('click', () => openRuleModal());
    document.getElementById('modal-close').addEventListener('click', closeModal);
    document.getElementById('modal-cancel').addEventListener('click', closeModal);
    document.getElementById('modal-save').addEventListener('click', saveRule);
    document.getElementById('export-rules-btn').addEventListener('click', exportRules);
    document.getElementById('import-rules-btn').addEventListener('click', () => document.getElementById('import-file').click());
    document.getElementById('import-file').addEventListener('change', importRules);
    document.getElementById('rules-search').addEventListener('input', filterRulesTable);
    document.getElementById('rules-filter-category').addEventListener('change', filterRulesTable);
    document.getElementById('rules-filter-type').addEventListener('change', filterRulesTable);
}

function loadRules() {
    fetch(`${API_BASE}/api/rules`)
        .then(r => r.json())
        .then(rules => {
            allRules = rules;
            renderRulesTable(rules);
            updateCategoryFilter(rules);
        });
}

function renderRulesTable(rules) {
    const tbody = document.getElementById('rules-tbody');
    tbody.innerHTML = rules.map(r => `
        <tr>
            <td><input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleRule(${r.id}, this.checked)"></td>
            <td class="${r.is_builtin ? 'builtin' : ''}">${r.name}</td>
            <td>${r.match_type}</td>
            <td class="pattern" title="${escapeHtml(r.pattern)}">${escapeHtml(r.pattern)}</td>
            <td class="${r.score > 0 ? 'score-positive' : 'score-negative'}">${r.score > 0 ? '+' : ''}${r.score}</td>
            <td>${r.category || '-'}</td>
            <td>
                <button class="btn btn-small" onclick="editRule(${r.id})">Edit</button>
                ${!r.is_builtin ? `<button class="btn btn-small btn-secondary" onclick="deleteRule(${r.id})">Delete</button>` : ''}
            </td>
        </tr>
    `).join('');
}

function updateCategoryFilter(rules) {
    const categories = [...new Set(rules.map(r => r.category).filter(c => c))];
    const select = document.getElementById('rules-filter-category');
    select.innerHTML = '<option value="">All Categories</option>' + 
        categories.map(c => `<option value="${c}">${c}</option>`).join('');
}

function filterRulesTable() {
    const search = document.getElementById('rules-search').value.toLowerCase();
    const category = document.getElementById('rules-filter-category').value;
    const type = document.getElementById('rules-filter-type').value;

    const filtered = allRules.filter(r => {
        if (search && !r.name.toLowerCase().includes(search) && !r.pattern.toLowerCase().includes(search)) return false;
        if (category && r.category !== category) return false;
        if (type === 'builtin' && !r.is_builtin) return false;
        if (type === 'custom' && r.is_builtin) return false;
        return true;
    });

    renderRulesTable(filtered);
}

function openRuleModal(rule = null) {
    document.getElementById('modal').style.display = 'flex';
    document.getElementById('modal-title').textContent = rule ? 'Edit Rule' : 'Add Rule';
    document.getElementById('rule-id').value = rule ? rule.id : '';
    document.getElementById('rule-name').value = rule ? rule.name : '';
    document.getElementById('rule-description').value = rule ? rule.description : '';
    document.getElementById('rule-match-type').value = rule ? rule.match_type : 'contains';
    document.getElementById('rule-pattern').value = rule ? rule.pattern : '';
    document.getElementById('rule-score').value = rule ? rule.score : 5;
    document.getElementById('rule-category').value = rule ? rule.category : '';
    document.getElementById('rule-enabled').checked = rule ? rule.enabled : true;
}

function closeModal() {
    document.getElementById('modal').style.display = 'none';
}

function saveRule() {
    const id = document.getElementById('rule-id').value;
    const rule = {
        name: document.getElementById('rule-name').value,
        description: document.getElementById('rule-description').value,
        match_type: document.getElementById('rule-match-type').value,
        pattern: document.getElementById('rule-pattern').value,
        score: parseInt(document.getElementById('rule-score').value),
        category: document.getElementById('rule-category').value,
        enabled: document.getElementById('rule-enabled').checked
    };

    const method = id ? 'PUT' : 'POST';
    const url = id ? `${API_BASE}/api/rules/${id}` : `${API_BASE}/api/rules`;

    fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rule)
    })
    .then(() => { closeModal(); loadRules(); })
    .catch(err => alert('Failed to save rule: ' + err.message));
}

function editRule(id) {
    const rule = allRules.find(r => r.id === id);
    if (rule) openRuleModal(rule);
}

function deleteRule(id) {
    if (!confirm('Delete this rule?')) return;
    fetch(`${API_BASE}/api/rules/${id}`, { method: 'DELETE' })
        .then(() => loadRules());
}

function toggleRule(id, enabled) {
    const rule = allRules.find(r => r.id === id);
    if (!rule) return;
    rule.enabled = enabled;
    fetch(`${API_BASE}/api/rules/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rule)
    });
}

function exportRules() {
    window.location.href = `${API_BASE}/api/rules/export`;
}

function importRules(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
        fetch(`${API_BASE}/api/rules/import`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: ev.target.result
        })
        .then(() => loadRules())
        .catch(err => alert('Import failed: ' + err.message));
    };
    reader.readAsText(file);
    e.target.value = '';
}

function loadConfig() {
    fetch(`${API_BASE}/api/config`)
        .then(r => r.json())
        .then(cfg => {
            const status = document.getElementById('llm-status');
            let html = '';
            
            if (!cfg.llm_configured) {
                html = `<div class="llm-status-item">
                    <span class="status-icon status-error">&#10007;</span>
                    <span>LLM not configured</span>
                </div>
                <p class="hint">Configure LLM in ./config/config.yaml (default) or use --config flag to specify a different path</p>`;
            } else if (cfg.llm_available) {
                html = `<div class="llm-status-item">
                    <span class="status-icon status-ok">&#10003;</span>
                    <span>LLM Available</span>
                </div>
                <div class="llm-details">
                    <div><strong>Provider:</strong> ${cfg.llm_provider}</div>
                    <div><strong>Model:</strong> ${cfg.llm_model}</div>
                </div>`;
            } else {
                html = `<div class="llm-status-item">
                    <span class="status-icon status-error">&#10007;</span>
                    <span>LLM Unavailable</span>
                </div>
                <div class="llm-details">
                    <div><strong>Provider:</strong> ${cfg.llm_provider}</div>
                    <div><strong>Model:</strong> ${cfg.llm_model}</div>
                    <div class="llm-error"><strong>Error:</strong> ${escapeHtml(cfg.llm_error || 'Unknown error')}</div>
                </div>`;
            }
            
            status.innerHTML = html;
            
            const llmCheckbox = document.getElementById('opt-llm');
            const llmLabel = llmCheckbox ? llmCheckbox.parentElement : null;
            if (llmCheckbox) {
                llmCheckbox.disabled = !cfg.llm_available;
                if (!cfg.llm_available) {
                    llmCheckbox.checked = false;
                    if (llmLabel) {
                        let reason = 'LLM not available';
                        if (!cfg.llm_configured) {
                            reason = 'LLM not configured. Set up in ./config/config.yaml (default) or use --config flag';
                        } else if (cfg.llm_error) {
                            reason = cfg.llm_error;
                        }
                        llmLabel.title = reason;
                        llmLabel.classList.add('disabled-option');
                    }
                } else {
                    if (llmLabel) {
                        llmLabel.title = '';
                        llmLabel.classList.remove('disabled-option');
                    }
                }
            }
        });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function notifyCompletion(message) {
    if (!('Notification' in window)) {
        return;
    }
    
    if (Notification.permission === 'granted') {
        new Notification('yarGen', { body: message, icon: '/favicon.ico' });
    } else if (Notification.permission !== 'denied') {
        Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
                new Notification('yarGen', { body: message, icon: '/favicon.ico' });
            }
        });
    }
}

function setupRuleNaming() {
    document.getElementById('suggest-name-btn').addEventListener('click', suggestRuleName);
    document.getElementById('copy-name-btn').addEventListener('click', () => {
        const name = document.getElementById('suggested-name-value').textContent;
        navigator.clipboard.writeText(name);
    });
    document.getElementById('apply-name-btn').addEventListener('click', applyRuleNameToOutput);
}

function setupSettingsPage() {
    const toggleBtn = document.getElementById('llm-help-toggle');
    const helpContent = document.getElementById('llm-help-content');
    
    if (toggleBtn && helpContent) {
        toggleBtn.addEventListener('click', () => {
            const isVisible = helpContent.style.display !== 'none';
            helpContent.style.display = isVisible ? 'none' : 'block';
            toggleBtn.textContent = isVisible ? 'Show Configuration Help' : 'Hide Configuration Help';
        });
    }
}

function loadTags() {
    fetch(`${API_BASE}/api/tags`)
        .then(r => r.json())
        .then(tags => {
            allTags = tags;
            renderTagCloud();
        })
        .catch(err => console.error('Failed to load tags:', err));
}

function renderTagCloud() {
    const categories = ['Main', 'Intent', 'Type', 'OS', 'Arch', 'Tech', 'Modifier'];
    
    categories.forEach(category => {
        const container = document.querySelector(`.tag-cloud[data-category="${category}"]`);
        if (!container) return;
        
        const categoryTags = allTags.filter(t => t.category === category);
        container.innerHTML = categoryTags.map(t => `
            <span class="tag" data-tag="${t.tag}" title="${escapeHtml(t.description)}">
                ${t.tag}
            </span>
        `).join('');
        
        container.querySelectorAll('.tag').forEach(tagEl => {
            tagEl.addEventListener('click', () => toggleTag(tagEl));
        });
    });
}

function toggleTag(tagEl) {
    const tag = tagEl.dataset.tag;
    const tagInfo = allTags.find(t => t.tag === tag);
    
    if (tagEl.classList.contains('selected')) {
        tagEl.classList.remove('selected');
        selectedTags = selectedTags.filter(t => t !== tag);
    } else {
        if (tagInfo && tagInfo.category === 'Main') {
            document.querySelectorAll('.tag-cloud[data-category="Main"] .tag.selected').forEach(el => {
                el.classList.remove('selected');
                selectedTags = selectedTags.filter(t => t !== el.dataset.tag);
            });
        }
        tagEl.classList.add('selected');
        selectedTags.push(tag);
    }
    
    updateSuggestButton();
}

function updateSuggestButton() {
    const hasMainTag = selectedTags.some(tag => {
        const info = allTags.find(t => t.tag === tag);
        return info && info.category === 'Main';
    });
    document.getElementById('suggest-name-btn').disabled = !hasMainTag || !currentJobId;
}

function suggestRuleName() {
    if (!currentJobId) return;
    
    const description = document.getElementById('rule-description-input').value;
    const btn = document.getElementById('suggest-name-btn');
    const resultDiv = document.getElementById('suggested-name-result');
    
    btn.disabled = true;
    btn.textContent = 'Suggesting...';
    resultDiv.style.display = 'none';
    
    fetch(`${API_BASE}/api/suggest-name`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            job_id: currentJobId,
            tags: selectedTags,
            description: description
        })
    })
    .then(r => r.json())
    .then(result => {
        if (result.error) {
            throw new Error(result.error);
        }
        
        document.getElementById('suggested-name-value').textContent = result.suggested_name;
        document.getElementById('suggested-tags-value').textContent = result.tags ? result.tags.join(', ') : '-';
        document.getElementById('suggested-reasoning-value').textContent = result.reasoning || '';
        resultDiv.style.display = 'block';
        
        btn.textContent = 'Suggest Rule Name';
        updateSuggestButton();
    })
    .catch(err => {
        alert('Failed to suggest name: ' + err.message);
        btn.textContent = 'Suggest Rule Name';
        updateSuggestButton();
    });
}

function applyRuleNameToOutput() {
    const newName = document.getElementById('suggested-name-value').textContent;
    if (!newName) return;
    
    const output = document.getElementById('rules-output');
    let rules = output.textContent;
    
    rules = rules.replace(/^rule\s+(\w+)\s*\{/gm, (match, oldName) => {
        return `rule ${newName} {`;
    });
    
    output.textContent = rules;
    
    const btn = document.getElementById('apply-name-btn');
    const originalText = btn.textContent;
    btn.textContent = 'Applied!';
    btn.disabled = true;
    setTimeout(() => {
        btn.textContent = originalText;
        btn.disabled = false;
    }, 1500);
}
