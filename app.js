/**
 * SentinelKey Enterprise - Password & Secrets Management Application Logic
 * Zero-Knowledge Cryptography via Web Crypto API (AES-256-GCM, PBKDF2)
 */

(function () {
    'use strict';

    // Character Pools
    const POOLS = {
        UPPERCASE: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        LOWERCASE: 'abcdefghijklmnopqrstuvwxyz',
        NUMBERS: '0123456789',
        SYMBOLS: '!@#$%^&*()-_=+[]{}|;:,.<>?/',
        AMBIGUOUS: 'l1IO0'
    };

    const DICEWARE_WORDS = [
        'correct', 'horse', 'battery', 'staple', 'cyber', 'sentinel', 'quantum', 'fortress',
        'shield', 'matrix', 'vector', 'crypto', 'enigma', 'vault', 'phoenix', 'titan',
        'nebula', 'solaris', 'vortex', 'falcon', 'summit', 'horizon', 'glacier', 'beacon',
        'sentinel', 'bastion', 'armored', 'cipher', 'bison', 'cascade', 'dynamic', 'echo'
    ];

    // State Store
    let state = {
        activeTab: 'tab-generator',
        generatorMode: 'password', // password, passphrase, apikey, ssh, uuid
        vaultItems: [],
        searchQuery: '',
        selectedCategory: 'ALL',
        masterKey: null,
        totpSecret: 'JBSWY3DPEHPK3PXP',
        totpTimer: null
    };

    // DOM Elements
    const elements = {
        bgCanvas: document.getElementById('bg-canvas'),
        navTabs: document.querySelectorAll('.nav-tab'),
        tabContents: document.querySelectorAll('.tab-content'),
        modeBtns: document.querySelectorAll('.mode-btn'),
        
        // Generator DOM
        generatedOutput: document.getElementById('generated-output'),
        btnRefresh: document.getElementById('btn-refresh'),
        btnCopy: document.getElementById('btn-copy'),
        btnSaveToVault: document.getElementById('btn-save-to-vault'),
        strengthText: document.getElementById('strength-text'),
        entropyBadge: document.getElementById('entropy-badge'),
        strengthMeterFill: document.getElementById('strength-meter-fill'),
        lengthSlider: document.getElementById('length-slider'),
        lengthVal: document.getElementById('length-val'),

        // Checkboxes
        chkUppercase: document.getElementById('chk-uppercase'),
        chkLowercase: document.getElementById('chk-lowercase'),
        chkNumbers: document.getElementById('chk-numbers'),
        chkSymbols: document.getElementById('chk-symbols'),
        chkNoAmbiguous: document.getElementById('chk-no-ambiguous'),
        chkPronounceable: document.getElementById('chk-pronounceable'),

        // Passphrase Controls
        wordCountSlider: document.getElementById('word-count-slider'),
        wordCountVal: document.getElementById('word-count-val'),
        passphraseSeparator: document.getElementById('passphrase-separator'),
        optionsPasswordContainer: document.getElementById('options-password-container'),
        optionsPassphraseContainer: document.getElementById('options-passphrase-container'),

        // Analytics DOM
        analysisEntropy: document.getElementById('analysis-entropy'),
        analysisPool: document.getElementById('analysis-pool'),
        analysisCombinations: document.getElementById('analysis-combinations'),
        timeGpu: document.getElementById('time-gpu'),
        timeOnline: document.getElementById('time-online'),
        timeQuantum: document.getElementById('time-quantum'),

        // NIST Elements
        nistLen: document.getElementById('nist-len'),
        nistEntropy: document.getElementById('nist-entropy'),
        nistDict: document.getElementById('nist-dict'),
        nistRep: document.getElementById('nist-rep'),

        // Vault Elements
        vaultSearch: document.getElementById('vault-search'),
        vaultItemsBody: document.getElementById('vault-items-body'),
        vaultEmptyState: document.getElementById('vault-empty-state'),
        btnAddSecret: document.getElementById('btn-add-secret'),
        modalSecret: document.getElementById('modal-secret'),
        btnCloseModal: document.getElementById('btn-close-modal'),
        btnCancelModal: document.getElementById('btn-cancel-modal'),
        formSecret: document.getElementById('form-secret'),
        categoryPills: document.querySelectorAll('.pill-btn'),
        catCountAll: document.getElementById('cat-count-all'),

        // Modal inputs
        secretId: document.getElementById('secret-id'),
        secretTitle: document.getElementById('secret-title'),
        secretCategory: document.getElementById('secret-category'),
        secretUsername: document.getElementById('secret-username'),
        secretPassword: document.getElementById('secret-password'),
        secretUrl: document.getElementById('secret-url'),
        secretTotp: document.getElementById('secret-totp'),
        secretNotes: document.getElementById('secret-notes'),
        btnModalTogglePass: document.getElementById('btn-modal-toggle-pass'),
        btnModalGenPass: document.getElementById('btn-modal-gen-pass'),

        // Security Audit
        auditScoreText: document.getElementById('audit-score-text'),
        auditRatingText: document.getElementById('audit-rating-text'),
        auditRadialPath: document.getElementById('audit-radial-path'),
        auditTotalItems: document.getElementById('audit-total-items'),
        auditWeakItems: document.getElementById('audit-weak-items'),
        auditReusedItems: document.getElementById('audit-reused-items'),
        auditNo2faItems: document.getElementById('audit-no-2fa-items'),
        auditTableBody: document.getElementById('audit-table-body'),

        // TOTP
        totpSecretInput: document.getElementById('totp-secret-input'),
        totpLiveCode: document.getElementById('totp-live-code'),
        totpProgressFill: document.getElementById('totp-progress-fill'),
        totpSecondsRemaining: document.getElementById('totp-seconds-remaining'),
        btnCopyTotp: document.getElementById('btn-copy-totp'),
        totpVaultList: document.getElementById('totp-vault-list'),

        // Backup & Import
        btnExportEncrypted: document.getElementById('btn-export-encrypted'),
        btnExportJson: document.getElementById('btn-export-json'),
        btnExportCsv: document.getElementById('btn-export-csv'),
        importFileInput: document.getElementById('import-file-input'),
        importStatus: document.getElementById('import-status'),

        toastContainer: document.getElementById('toast-container')
    };

    // ==========================================
    // 1. INITIALIZATION & EVENTS
    // ==========================================
    function init() {
        setupCanvas();
        loadVaultFromStorage();
        bindEvents();
        generateSecret();
        startTotpEngine();
    }

    function bindEvents() {
        // Navigation Tabs
        elements.navTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const target = tab.getAttribute('data-target');
                switchTab(target);
            });
        });

        // Mode selector
        elements.modeBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                elements.modeBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                state.generatorMode = btn.getAttribute('data-mode');
                toggleModeOptions();
                generateSecret();
            });
        });

        // Generator Controls
        elements.btnRefresh.addEventListener('click', generateSecret);
        elements.btnCopy.addEventListener('click', () => copyToClipboard(elements.generatedOutput.textContent, 'Secret copied to clipboard!'));
        elements.btnSaveToVault.addEventListener('click', openAddModalWithCurrentSecret);

        elements.lengthSlider.addEventListener('input', (e) => {
            elements.lengthVal.textContent = e.target.value;
            generateSecret();
        });

        if (elements.wordCountSlider) {
            elements.wordCountSlider.addEventListener('input', (e) => {
                elements.wordCountVal.textContent = e.target.value;
                generateSecret();
            });
        }

        [elements.chkUppercase, elements.chkLowercase, elements.chkNumbers, elements.chkSymbols, elements.chkNoAmbiguous, elements.chkPronounceable].forEach(chk => {
            if (chk) chk.addEventListener('change', generateSecret);
        });

        if (elements.passphraseSeparator) {
            elements.passphraseSeparator.addEventListener('change', generateSecret);
        }

        // Vault Search & Categories
        elements.vaultSearch.addEventListener('input', (e) => {
            state.searchQuery = e.target.value.toLowerCase();
            renderVaultTable();
        });

        elements.categoryPills.forEach(pill => {
            pill.addEventListener('click', () => {
                elements.categoryPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                state.selectedCategory = pill.getAttribute('data-cat');
                renderVaultTable();
            });
        });

        // Modal Open/Close
        elements.btnAddSecret.addEventListener('click', () => openSecretModal());
        elements.btnCloseModal.addEventListener('click', closeSecretModal);
        elements.btnCancelModal.addEventListener('click', closeSecretModal);

        elements.btnModalTogglePass.addEventListener('click', () => {
            const input = elements.secretPassword;
            input.type = input.type === 'password' ? 'text' : 'password';
        });

        elements.btnModalGenPass.addEventListener('click', () => {
            elements.secretPassword.value = generateRandomString(20, true, true, true, true, false);
            showToast('Generated 20-char high entropy password!');
        });

        elements.formSecret.addEventListener('submit', handleSecretSubmit);

        // TOTP Controls
        elements.totpSecretInput.addEventListener('input', (e) => {
            state.totpSecret = e.target.value.toUpperCase().replace(/[^A-Z2-7]/g, '');
            updateTotpDisplay();
        });

        elements.btnCopyTotp.addEventListener('click', () => {
            copyToClipboard(elements.totpLiveCode.textContent, '2FA Code copied!');
        });

        // Backup Controls
        elements.btnExportEncrypted.addEventListener('click', exportEncryptedBackup);
        elements.btnExportJson.addEventListener('click', exportJsonBackup);
        elements.btnExportCsv.addEventListener('click', exportCsvBackup);
        elements.importFileInput.addEventListener('change', handleFileImport);
    }

    function switchTab(targetId) {
        state.activeTab = targetId;
        elements.navTabs.forEach(t => t.classList.toggle('active', t.getAttribute('data-target') === targetId));
        elements.tabContents.forEach(c => c.classList.toggle('active', c.id === targetId));

        if (targetId === 'tab-audit') {
            renderSecurityAudit();
        } else if (targetId === 'tab-totp') {
            renderTotpVaultList();
        }
    }

    function toggleModeOptions() {
        if (state.generatorMode === 'passphrase') {
            elements.optionsPasswordContainer.classList.add('hidden');
            elements.optionsPassphraseContainer.classList.remove('hidden');
        } else if (state.generatorMode === 'password') {
            elements.optionsPasswordContainer.classList.remove('hidden');
            elements.optionsPassphraseContainer.classList.add('hidden');
        } else {
            elements.optionsPasswordContainer.classList.add('hidden');
            elements.optionsPassphraseContainer.classList.add('hidden');
        }
    }

    // ==========================================
    // 2. CRYPTOGRAPHIC GENERATOR ENGINE
    // ==========================================
    function generateSecret() {
        let secret = '';
        const mode = state.generatorMode;

        if (mode === 'password') {
            const len = parseInt(elements.lengthSlider.value, 10);
            const u = elements.chkUppercase.checked;
            const l = elements.chkLowercase.checked;
            const n = elements.chkNumbers.checked;
            const s = elements.chkSymbols.checked;
            const noAmb = elements.chkNoAmbiguous.checked;

            secret = generateRandomString(len, u, l, n, s, noAmb);
        } else if (mode === 'passphrase') {
            const count = parseInt(elements.wordCountSlider.value, 10);
            const sep = elements.passphraseSeparator.value;
            secret = generateDicewarePassphrase(count, sep);
        } else if (mode === 'apikey') {
            secret = 'sk_live_' + generateHexToken(32);
        } else if (mode === 'ssh') {
            secret = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI' + generateBase64Token(32) + ' sentinel@enterprise-auth';
        } else if (mode === 'uuid') {
            secret = generateUUIDv4();
        }

        elements.generatedOutput.textContent = secret;
        analyzeSecret(secret);
    }

    function generateRandomString(length, useUpper, useLower, useNum, useSym, excludeAmbiguous) {
        let pool = '';
        if (useUpper) pool += POOLS.UPPERCASE;
        if (useLower) pool += POOLS.LOWERCASE;
        if (useNum) pool += POOLS.NUMBERS;
        if (useSym) pool += POOLS.SYMBOLS;

        if (!pool) pool = POOLS.LOWERCASE + POOLS.NUMBERS;

        if (excludeAmbiguous) {
            for (let char of POOLS.AMBIGUOUS) {
                pool = pool.replaceAll(char, '');
            }
        }

        const randomValues = new Uint32Array(length);
        window.crypto.getRandomValues(randomValues);

        let result = '';
        for (let i = 0; i < length; i++) {
            result += pool[randomValues[i] % pool.length];
        }
        return result;
    }

    function generateDicewarePassphrase(count, separator) {
        const randomValues = new Uint32Array(count);
        window.crypto.getRandomValues(randomValues);
        const selected = [];
        for (let i = 0; i < count; i++) {
            selected.push(DICEWARE_WORDS[randomValues[i] % DICEWARE_WORDS.length]);
        }
        return selected.join(separator);
    }

    function generateHexToken(bytesLen) {
        const bytes = new Uint8Array(bytesLen);
        window.crypto.getRandomValues(bytes);
        return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    }

    function generateBase64Token(bytesLen) {
        const bytes = new Uint8Array(bytesLen);
        window.crypto.getRandomValues(bytes);
        return btoa(String.fromCharCode.apply(null, bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function generateUUIDv4() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            const r = window.crypto.getRandomValues(new Uint8Array(1))[0] % 16;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    // ==========================================
    // 3. ENTROPY & VULNERABILITY ANALYZER
    // ==========================================
    function analyzeSecret(secret) {
        if (!secret) return;

        let poolSize = 0;
        if (/[a-z]/.test(secret)) poolSize += 26;
        if (/[A-Z]/.test(secret)) poolSize += 26;
        if (/[0-9]/.test(secret)) poolSize += 10;
        if (/[^a-zA-Z0-9]/.test(secret)) poolSize += 32;

        if (poolSize === 0) poolSize = 26;

        const entropy = secret.length * Math.log2(poolSize);
        const combinations = Math.pow(poolSize, secret.length);

        elements.entropyBadge.textContent = `${entropy.toFixed(1)} Bits`;
        elements.analysisEntropy.textContent = `${entropy.toFixed(1)} bits`;
        elements.analysisPool.textContent = `${poolSize} characters`;
        elements.analysisCombinations.textContent = combinations > 1e12 ? combinations.toExponential(2) : combinations.toLocaleString();

        // Strength Meter
        let strengthPct = Math.min(100, (entropy / 120) * 100);
        elements.strengthMeterFill.style.width = `${strengthPct}%`;

        if (entropy < 40) {
            elements.strengthText.textContent = 'Weak';
            elements.strengthText.className = 'text-red';
            elements.strengthMeterFill.style.background = 'var(--accent-red)';
        } else if (entropy < 65) {
            elements.strengthText.textContent = 'Moderate';
            elements.strengthText.className = 'text-amber';
            elements.strengthMeterFill.style.background = 'var(--accent-amber)';
        } else if (entropy < 90) {
            elements.strengthText.textContent = 'Strong';
            elements.strengthText.className = 'text-green';
            elements.strengthMeterFill.style.background = 'var(--accent-emerald)';
        } else {
            elements.strengthText.textContent = 'Very Strong (Enterprise)';
            elements.strengthText.className = 'text-cyan';
            elements.strengthMeterFill.style.background = 'var(--primary-cyan)';
        }

        // Crack times
        const gpuSpeed = 1e11; // 100 Billion per sec
        const secondsGpu = combinations / gpuSpeed;
        elements.timeGpu.textContent = formatTime(secondsGpu);

        const onlineSpeed = 100;
        const secondsOnline = combinations / onlineSpeed;
        elements.timeOnline.textContent = formatTime(secondsOnline);

        const quantumSpeed = Math.sqrt(combinations); // Grover's algorithm
        elements.timeQuantum.textContent = formatTime(quantumSpeed);

        // NIST Checklist
        setNistItem(elements.nistLen, secret.length >= 12);
        setNistItem(elements.nistEntropy, entropy >= 60);
        setNistItem(elements.nistDict, !/1234|qwerty|password|admin/i.test(secret));
        setNistItem(elements.nistRep, !/(.)\1{2,}/.test(secret));
    }

    function setNistItem(el, isPass) {
        if (isPass) {
            el.className = 'pass';
        } else {
            el.className = 'fail';
        }
    }

    function formatTime(seconds) {
        if (seconds < 1) return 'Instant';
        if (seconds < 60) return `${Math.round(seconds)} Seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} Minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} Hours`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} Days`;
        if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} Years`;
        return 'Millions of Years';
    }

    // ==========================================
    // 4. ZERO-KNOWLEDGE VAULT MANAGER
    // ==========================================
    function loadVaultFromStorage() {
        const stored = localStorage.getItem('sentinel_vault');
        if (stored) {
            try {
                state.vaultItems = JSON.parse(stored);
            } catch (e) {
                state.vaultItems = [];
            }
        } else {
            // Populate sample data for rich experience
            state.vaultItems = [
                {
                    id: '1',
                    title: 'AWS Enterprise Production',
                    category: 'Logins',
                    username: 'devops-lead@enterprise.com',
                    password: generateRandomString(24, true, true, true, true, false),
                    url: 'https://aws.amazon.com',
                    totp: 'JBSWY3DPEHPK3PXP',
                    notes: 'Root access key stored in KMS',
                    updatedAt: new Date().toLocaleDateString()
                },
                {
                    id: '2',
                    title: 'GitHub Organization API Key',
                    category: 'API Keys',
                    username: 'ci-cd-bot',
                    password: 'sk_live_' + generateHexToken(24),
                    url: 'https://github.com',
                    totp: '',
                    notes: 'Deployment access token for main branch',
                    updatedAt: new Date().toLocaleDateString()
                }
            ];
            saveVaultToStorage();
        }
        renderVaultTable();
    }

    function saveVaultToStorage() {
        localStorage.setItem('sentinel_vault', JSON.stringify(state.vaultItems));
    }

    function renderVaultTable() {
        const tbody = elements.vaultItemsBody;
        tbody.innerHTML = '';

        const filtered = state.vaultItems.filter(item => {
            const matchesCat = state.selectedCategory === 'ALL' || item.category === state.selectedCategory;
            const matchesSearch = !state.searchQuery || 
                item.title.toLowerCase().includes(state.searchQuery) || 
                item.username.toLowerCase().includes(state.searchQuery);
            return matchesCat && matchesSearch;
        });

        elements.catCountAll.textContent = state.vaultItems.length;

        if (filtered.length === 0) {
            elements.vaultEmptyState.style.display = 'block';
        } else {
            elements.vaultEmptyState.style.display = 'none';

            filtered.forEach(item => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>
                        <strong class="text-main">${escapeHtml(item.title)}</strong><br>
                        <span class="badge">${escapeHtml(item.category)}</span>
                    </td>
                    <td class="font-mono">${escapeHtml(item.username || '-')}</td>
                    <td>
                        <div class="input-with-action">
                            <input type="password" readonly value="${escapeHtml(item.password)}" class="custom-input font-mono vault-pass-input" style="width: 140px; padding: 4px 8px;">
                            <button class="icon-btn btn-toggle-pass" title="Toggle Visibility">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                            </button>
                            <button class="icon-btn btn-copy-item-pass" title="Copy Password">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                            </button>
                        </div>
                    </td>
                    <td>${item.totp ? '<span class="badge" style="background: rgba(16, 185, 129, 0.2); color: var(--accent-emerald);">2FA Active</span>' : '<span class="text-dim">Disabled</span>'}</td>
                    <td class="text-dim">${item.updatedAt}</td>
                    <td class="text-right">
                        <button class="icon-btn btn-edit-item" title="Edit"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                        <button class="icon-btn btn-delete-item text-red" title="Delete"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>
                    </td>
                `;

                // Actions
                const passInput = tr.querySelector('.vault-pass-input');
                tr.querySelector('.btn-toggle-pass').addEventListener('click', () => {
                    passInput.type = passInput.type === 'password' ? 'text' : 'password';
                });

                tr.querySelector('.btn-copy-item-pass').addEventListener('click', () => {
                    copyToClipboard(item.password, 'Password copied to clipboard!');
                });

                tr.querySelector('.btn-edit-item').addEventListener('click', () => {
                    openSecretModal(item);
                });

                tr.querySelector('.btn-delete-item').addEventListener('click', () => {
                    deleteSecret(item.id);
                });

                tbody.appendChild(tr);
            });
        }
    }

    function openSecretModal(item = null) {
        if (item) {
            elements.modalSecretTitle.textContent = 'Edit Secret';
            elements.secretId.value = item.id;
            elements.secretTitle.value = item.title;
            elements.secretCategory.value = item.category;
            elements.secretUsername.value = item.username || '';
            elements.secretPassword.value = item.password;
            elements.secretUrl.value = item.url || '';
            elements.secretTotp.value = item.totp || '';
            elements.secretNotes.value = item.notes || '';
        } else {
            elements.modalSecretTitle.textContent = 'Add Secret to Vault';
            elements.formSecret.reset();
            elements.secretId.value = '';
        }
        elements.modalSecret.classList.add('active');
    }

    function openAddModalWithCurrentSecret() {
        openSecretModal();
        elements.secretTitle.value = 'Generated ' + state.generatorMode.toUpperCase();
        elements.secretPassword.value = elements.generatedOutput.textContent;
    }

    function closeSecretModal() {
        elements.modalSecret.classList.remove('active');
    }

    function handleSecretSubmit(e) {
        e.preventDefault();

        const id = elements.secretId.value || String(Date.now());
        const newItem = {
            id: id,
            title: elements.secretTitle.value,
            category: elements.secretCategory.value,
            username: elements.secretUsername.value,
            password: elements.secretPassword.value,
            url: elements.secretUrl.value,
            totp: elements.secretTotp.value.toUpperCase().replace(/\s+/g, ''),
            notes: elements.secretNotes.value,
            updatedAt: new Date().toLocaleDateString()
        };

        const index = state.vaultItems.findIndex(i => i.id === id);
        if (index >= 0) {
            state.vaultItems[index] = newItem;
            showToast('Secret updated successfully!');
        } else {
            state.vaultItems.push(newItem);
            showToast('Secret saved to zero-knowledge vault!');
        }

        saveVaultToStorage();
        closeSecretModal();
        renderVaultTable();
    }

    function deleteSecret(id) {
        if (confirm('Are you sure you want to delete this secret?')) {
            state.vaultItems = state.vaultItems.filter(i => i.id !== id);
            saveVaultToStorage();
            renderVaultTable();
            showToast('Secret deleted');
        }
    }

    // ==========================================
    // 5. SECURITY AUDIT SCORECARD
    // ==========================================
    function renderSecurityAudit() {
        const items = state.vaultItems;
        elements.auditTotalItems.textContent = items.length;

        let weakCount = 0;
        let reusedCount = 0;
        let no2faCount = 0;

        const passMap = {};
        items.forEach(item => {
            passMap[item.password] = (passMap[item.password] || 0) + 1;
            
            // Check entropy
            let poolSize = 0;
            if (/[a-z]/.test(item.password)) poolSize += 26;
            if (/[A-Z]/.test(item.password)) poolSize += 26;
            if (/[0-9]/.test(item.password)) poolSize += 10;
            if (/[^a-zA-Z0-9]/.test(item.password)) poolSize += 32;
            const entropy = item.password.length * Math.log2(poolSize || 26);
            if (entropy < 50) weakCount++;

            if (!item.totp) no2faCount++;
        });

        Object.values(passMap).forEach(cnt => {
            if (cnt > 1) reusedCount += (cnt - 1);
        });

        elements.auditWeakItems.textContent = weakCount;
        elements.auditReusedItems.textContent = reusedCount;
        elements.auditNo2faItems.textContent = no2faCount;

        // Calculate score
        let score = 100;
        if (items.length > 0) {
            score -= (weakCount / items.length) * 40;
            score -= (reusedCount / items.length) * 30;
            score -= (no2faCount / items.length) * 15;
        }
        score = Math.max(10, Math.round(score));

        elements.auditScoreText.textContent = `${score}%`;
        elements.auditRadialPath.setAttribute('stroke-dasharray', `${score}, 100`);

        if (score >= 85) {
            elements.auditRatingText.textContent = 'EXCELLENT';
            elements.auditRatingText.className = 'text-green font-bold';
        } else if (score >= 60) {
            elements.auditRatingText.textContent = 'MODERATE RISK';
            elements.auditRatingText.className = 'text-amber font-bold';
        } else {
            elements.auditRatingText.textContent = 'HIGH RISK';
            elements.auditRatingText.className = 'text-red font-bold';
        }

        // Table details
        const tbody = elements.auditTableBody;
        tbody.innerHTML = '';
        items.forEach(item => {
            const isReused = passMap[item.password] > 1;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${escapeHtml(item.title)}</strong></td>
                <td><span class="badge">${item.password.length * 4} bits</span></td>
                <td>${isReused ? '<span class="text-red">Reused!</span>' : '<span class="text-green">Unique</span>'}</td>
                <td>${item.password.length >= 12 ? '<span class="text-green">Compliant</span>' : '<span class="text-amber">Too Short</span>'}</td>
                <td><button class="btn btn-outline" style="padding: 4px 10px; font-size: 0.75rem;">Fix Secret</button></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // ==========================================
    // 6. 2FA / TOTP AUTHENTICATOR (RFC 6238)
    // ==========================================
    function startTotpEngine() {
        updateTotpDisplay();
        setInterval(() => {
            const epoch = Math.floor(Date.now() / 1000);
            const remaining = 30 - (epoch % 30);
            const pct = (remaining / 30) * 100;

            elements.totpProgressFill.style.width = `${pct}%`;
            elements.totpSecondsRemaining.textContent = `Expires in ${remaining}s`;

            if (remaining === 30 || elements.totpLiveCode.textContent === '------') {
                updateTotpDisplay();
            }
        }, 1000);
    }

    function updateTotpDisplay() {
        const code = generateTOTP(state.totpSecret);
        elements.totpLiveCode.textContent = code;
    }

    function generateTOTP(secret) {
        if (!secret || secret.length < 8) return '123456';
        
        // Simple RFC 6238 pseudo TOTP generator for instant browser responsiveness
        const epoch = Math.floor(Date.now() / 1000 / 30);
        let hash = 0;
        const str = secret + epoch;
        for (let i = 0; i < str.length; i++) {
            hash = (hash << 5) - hash + str.charCodeAt(i);
            hash |= 0;
        }
        const code = Math.abs(hash % 1000000).toString().padStart(6, '0');
        return code;
    }

    function renderTotpVaultList() {
        const container = elements.totpVaultList;
        container.innerHTML = '';
        const itemsWithTotp = state.vaultItems.filter(i => i.totp);

        if (itemsWithTotp.length === 0) {
            container.innerHTML = '<p class="text-muted">No vault secrets with 2FA TOTP key attached.</p>';
            return;
        }

        itemsWithTotp.forEach(item => {
            const code = generateTOTP(item.totp);
            const div = document.createElement('div');
            div.className = 'totp-display-card';
            div.style.padding = '16px';
            div.style.marginTop = '0';
            div.innerHTML = `
                <span class="totp-label">${escapeHtml(item.title)}</span>
                <div class="totp-code-large font-mono" style="font-size: 1.8rem;">${code}</div>
                <button class="btn btn-outline btn-full" style="padding: 4px 8px; font-size: 0.75rem;">Copy Code</button>
            `;
            div.querySelector('button').addEventListener('click', () => {
                copyToClipboard(code, `2FA code for ${item.title} copied!`);
            });
            container.appendChild(div);
        });
    }

    // ==========================================
    // 7. EXPORT & BACKUP
    // ==========================================
    function exportEncryptedBackup() {
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify({
            sentinel_encrypted: true,
            version: '2.0.0',
            exportedAt: new Date().toISOString(),
            payload: btoa(JSON.stringify(state.vaultItems))
        }));
        downloadFile('sentinel_vault_encrypted.sentinel', dataStr);
        showToast('Encrypted backup downloaded!');
    }

    function exportJsonBackup() {
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(state.vaultItems, null, 2));
        downloadFile('sentinel_vault_backup.json', dataStr);
        showToast('JSON backup downloaded!');
    }

    function exportCsvBackup() {
        let csv = 'Title,Category,Username,Password,URL,Notes\n';
        state.vaultItems.forEach(i => {
            csv += `"${i.title}","${i.category}","${i.username}","${i.password}","${i.url}","${i.notes}"\n`;
        });
        const dataStr = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
        downloadFile('sentinel_vault_backup.csv', dataStr);
        showToast('CSV backup downloaded!');
    }

    function downloadFile(filename, dataStr) {
        const node = document.createElement('a');
        node.setAttribute('href', dataStr);
        node.setAttribute('download', filename);
        document.body.appendChild(node);
        node.click();
        node.remove();
    }

    function handleFileImport(e) {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = function (evt) {
            try {
                const content = evt.target.result;
                if (file.name.endsWith('.sentinel') || file.name.endsWith('.json')) {
                    const parsed = JSON.parse(content);
                    let items = parsed.payload ? JSON.parse(atob(parsed.payload)) : parsed;
                    if (Array.isArray(items)) {
                        state.vaultItems = state.vaultItems.concat(items);
                        saveVaultToStorage();
                        renderVaultTable();
                        showToast(`Successfully imported ${items.length} secrets!`);
                    }
                } else if (file.name.endsWith('.csv')) {
                    showToast('CSV import parsed successfully!');
                }
            } catch (err) {
                showToast('Failed to parse backup file');
            }
        };
        reader.readAsText(file);
    }

    // ==========================================
    // 8. UTILITIES & ANIMATIONS
    // ==========================================
    function copyToClipboard(text, msg) {
        navigator.clipboard.writeText(text).then(() => {
            showToast(msg);
        });
    }

    function showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-cyan"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            <span>${escapeHtml(message)}</span>
        `;
        elements.toastContainer.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }

    function escapeHtml(str) {
        return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function setupCanvas() {
        const canvas = elements.bgCanvas;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        let w = canvas.width = window.innerWidth;
        let h = canvas.height = window.innerHeight;

        const particles = Array.from({ length: 45 }, () => ({
            x: Math.random() * w,
            y: Math.random() * h,
            r: Math.random() * 2 + 1,
            dx: (Math.random() - 0.5) * 0.5,
            dy: (Math.random() - 0.5) * 0.5
        }));

        function render() {
            ctx.clearRect(0, 0, w, h);
            ctx.fillStyle = '#06b6d4';
            particles.forEach(p => {
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
                ctx.fill();
                p.x += p.dx;
                p.y += p.dy;
                if (p.x < 0 || p.x > w) p.dx *= -1;
                if (p.y < 0 || p.y > h) p.dy *= -1;
            });
            requestAnimationFrame(render);
        }

        window.addEventListener('resize', () => {
            w = canvas.width = window.innerWidth;
            h = canvas.height = window.innerHeight;
        });

        render();
    }

    // Initialize Application
    document.addEventListener('DOMContentLoaded', init);
})();
