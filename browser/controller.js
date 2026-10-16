// Browser controller for form submissions protected by a proof-of-work challenge.

const controller = {
    worker: null,
    form: null,
    panel: null,
    status: null,
    progress: null,
    serverUrl: window.location.origin,
    workerId: null,
    pendingForm: null,
    readyPromise: null,
    poolSearchButton: null,
    stopPoolSearchButton: null,
    poolSearchStatus: null,
    poolSearchActive: false,
    poolSearchBatches: 0,
    poolSearchVerifiedBatches: 0,
    poolSearchWorkers: [],
    poolSearchForForm: false,
    minimalMode: false,
    poolSearchStartedAt: null,
    poolSearchTimer: null,
    pendingFormToken: null,

    init() {
        this.form = document.getElementById('contact-form');
        this.panel = document.getElementById('challenge-panel');
        this.poolSearchPanel = document.getElementById('pool-search-panel');
        this.status = document.getElementById('status');
        this.progress = document.getElementById('progress');
        this.submitButton = document.getElementById('submit-form');
        this.cancelButton = document.getElementById('cancel-challenge');
        this.poolSearchButton = document.getElementById('start-pool-search');
        this.stopPoolSearchButton = document.getElementById('stop-pool-search');
        this.poolSearchStatus = document.getElementById('pool-search-status');
        this.minimalMode = new URLSearchParams(window.location.search).get('mode') === 'minimal';
        if (this.minimalMode) {
            document.documentElement.classList.add('minimal-mode');
            this.panel.hidden = true;
            this.poolSearchPanel.hidden = true;
            document.getElementById('form-description').textContent =
                'Submitting waits for the pool to accept a share. This can take a very long time; ' +
                'the demo validates but does not store or deliver form submissions.';
        }
        this.workerId = sessionStorage.getItem('c2a-worker-id') || crypto.randomUUID();
        sessionStorage.setItem('c2a-worker-id', this.workerId);
        if (this.minimalMode) {
            this.form.addEventListener('submit', (event) => this.prepareForm(event));
            return;
        }
        this.worker = new Worker('/browser/challenger.js');

        this.worker.onmessage = (event) => {
            if (event.data.type === 'ready') {
                if (!event.data.data.moduleLoaded) {
                    const error = new Error(event.data.data.error || 'WASM challenger is unavailable');
                    this.setStatus(error.message);
                    this.readyPromiseReject(error);
                    return;
                }
                this.readyPromiseResolve();
            }
            this.handleWorkerMessage(event);
        };

        this.readyPromise = new Promise((resolve, reject) => {
            this.readyPromiseResolve = resolve;
            this.readyPromiseReject = reject;
            this.worker.onerror = () => reject(new Error('Challenger failed to load'));
            setTimeout(() => reject(new Error('Challenger initialization timed out')), 10000);
        });
        this.readyPromise.catch(() => {});
        this.form.addEventListener('submit', (event) => this.prepareForm(event));
        this.cancelButton.addEventListener('click', () => this.cancelChallenge());
        this.poolSearchButton.addEventListener('click', () => this.startPoolSearch());
        this.stopPoolSearchButton.addEventListener('click', () => this.stopPoolSearch());
        this.worker.postMessage({ type: 'init' });
    },

    prepareForm(event) {
        event.preventDefault();
        if (this.poolSearchActive) {
            this.poolSearchStatus.textContent = 'Stop the pool search before submitting the form.';
            return;
        }
        if (!this.form.reportValidity()) return;
        this.pendingForm = Object.fromEntries(new FormData(this.form).entries());
        if (this.minimalMode && this.pendingFormToken) {
            this.retryMinimalFormSubmission();
            return;
        }
        if (this.minimalMode) {
            this.setFormEnabled(false);
            this.startPoolSearch(true);
            return;
        }
        this.setFormEnabled(false);
        this.poolSearchButton.disabled = true;
        this.panel.hidden = false;
        this.cancelButton.disabled = false;
        this.setStatus('Verifying proof of work...');
        this.startChallenge();
    },

    async startChallenge() {
        if (!this.pendingForm) {
            this.setStatus('Submit the form before starting verification.');
            return;
        }
        this.cancelButton.disabled = false;
        try {
            this.setStatus('Preparing proof-of-work verification...');
            await this.readyPromise;

            this.setStatus('Issuing a form-scoped challenge...');
            const challenge = await this.issueChallenge();

            this.setStatus('Requesting an exclusive live-pool work lease...');
            const lease = await this.requestLease(challenge.challenge_id);
            this.setStatus('Proof-of-work job ready; verification is in progress.');
            this.worker.postMessage({
                type: 'solve',
                data: { ...lease, challenge_id: challenge.challenge_id }
            });
        } catch (error) {
            console.error('Form challenge failed:', error);
            this.setStatus('Challenge failed: ' + error.message);
            this.cancelButton.disabled = false;
            this.poolSearchButton.disabled = false;
        }
    },

    async startPoolSearch(forForm = false) {
        if (this.poolSearchActive) return;
        this.poolSearchActive = true;
        this.poolSearchForForm = forForm;
        this.poolSearchBatches = 0;
        this.poolSearchVerifiedBatches = 0;
        const workerCount = Math.min(4, Math.max(1, navigator.hardwareConcurrency || 2));
        if (forForm) {
            this.startPoolSearchTimer();
            this.submitButton.title = '';
            this.submitButton.removeAttribute('aria-label');
            this.setMinimalButtonLabel('Searching... 0.0s');
        } else {
            this.poolSearchButton.disabled = true;
            this.stopPoolSearchButton.disabled = false;
            this.submitButton.disabled = true;
            this.poolSearchStatus.textContent =
                `Preparing live pool search with ${workerCount} browser worker(s)...`;
        }
        for (let index = 0; index < workerCount; index++) {
            if (!this.poolSearchActive) break;
            try {
                const worker = new Worker('/browser/challenger.js');
                const poolWorker = { worker, index: index + 1 };
                this.poolSearchWorkers.push(poolWorker);
                worker.onmessage = (event) => this.handlePoolWorkerMessage(poolWorker, event);
                worker.onerror = () => {
                    if (this.poolSearchActive && this.poolSearchWorkers.includes(poolWorker)) {
                        this.finishPoolSearch('Pool search worker failed to load.');
                    }
                };
                worker.postMessage({ type: 'init' });
            } catch (error) {
                this.finishPoolSearch('Pool search could not start: ' + error.message);
                break;
            }
        }
    },

    async requestNextPoolBatch(poolWorker) {
        if (!this.poolSearchActive || !this.poolSearchWorkers.includes(poolWorker)) return;
        try {
            // Batches earn no token, in minimal mode too: the form's token
            // comes from one form proof once the pool accepts a share.
            const challenge = await this.issueChallenge('/pool/share-search');
            if (!this.poolSearchActive || !this.poolSearchWorkers.includes(poolWorker)) return;
            const lease = await this.requestLease(challenge.challenge_id);
            if (!this.poolSearchActive || !this.poolSearchWorkers.includes(poolWorker)) return;
            this.poolSearchBatches++;
            this.poolSearchStatus.textContent =
                `Searching live pool work with ${this.poolSearchWorkers.length} browser worker(s); ` +
                `${this.poolSearchVerifiedBatches} batch proofs verified; no pool share found yet.`;
            poolWorker.worker.postMessage({
                type: 'solve-pool-batch',
                data: { ...lease, challenge_id: challenge.challenge_id }
            });
        } catch (error) {
            if (!this.poolSearchActive || !this.poolSearchWorkers.includes(poolWorker)) return;
            this.finishPoolSearch('Pool search failed: ' + error.message);
        }
    },

    async handlePoolBatchProof(proof, poolWorker) {
        if (!this.poolSearchActive || !this.poolSearchWorkers.includes(poolWorker)) return;
        this.poolSearchStatus.textContent =
            `Verifying a browser batch against the live pool job...`;
        try {
            const result = await this.submitProof(proof);
            if (!this.poolSearchActive || !this.poolSearchWorkers.includes(poolWorker)) return;
            this.poolSearchVerifiedBatches++;
            if (this.poolSearchForForm) {
                if (result.pool_share === 'pool_accepted') {
                    await this.startMinimalFormProof(poolWorker);
                } else if ([
                    'not_pool_qualified',
                    'pool_rejected',
                    'duplicate_not_forwarded'
                ].includes(result.pool_share)) {
                    await this.requestNextPoolBatch(poolWorker);
                } else {
                    this.finishPoolSearch(`Pool share submission failed: ${result.pool_share}`);
                }
                return;
            }
            if (result.pool_share === 'not_pool_qualified' && this.poolSearchActive) {
                this.poolSearchStatus.textContent =
                    `${this.poolSearchVerifiedBatches} browser batch proofs verified across ` +
                    `${this.poolSearchWorkers.length} workers; no pool share found.`;
                await this.requestNextPoolBatch(poolWorker);
            } else {
                this.finishPoolSearch(`Pool share outcome: ${result.pool_share}`);
            }
        } catch (error) {
            if (!this.poolSearchActive || !this.poolSearchWorkers.includes(poolWorker)) return;
            this.finishPoolSearch('Pool batch verification failed: ' + error.message);
        }
    },

    finishPoolSearch(message) {
        if (!this.poolSearchActive) return;
        const wasFormSearch = this.poolSearchForForm;
        this.stopPoolWorkers();
        if (wasFormSearch) {
            this.poolSearchForForm = false;
            this.stopPoolSearchTimer();
            this.setFormEnabled(true);
            this.setMinimalButtonLabel('Search failed - retry');
            this.submitButton.title = message;
            this.submitButton.setAttribute('aria-label', `Search failed: ${message}. Click to retry.`);
            console.error(message);
        } else {
            this.poolSearchButton.disabled = false;
            this.stopPoolSearchButton.disabled = true;
            this.submitButton.disabled = false;
            this.poolSearchStatus.textContent = message;
        }
    },

    stopPoolWorkers() {
        this.poolSearchActive = false;
        for (const poolWorker of this.poolSearchWorkers) {
            poolWorker.worker.terminate();
        }
        this.poolSearchWorkers = [];
    },

    startPoolSearchTimer() {
        this.stopPoolSearchTimer();
        this.poolSearchStartedAt = performance.now();
        this.poolSearchTimer = setInterval(() => {
            const elapsed = ((performance.now() - this.poolSearchStartedAt) / 1000).toFixed(1);
            this.setMinimalButtonLabel(`Searching... ${elapsed}s`);
        }, 100);
    },

    stopPoolSearchTimer() {
        if (this.poolSearchTimer !== null) {
            clearInterval(this.poolSearchTimer);
            this.poolSearchTimer = null;
        }
    },

    getPoolSearchElapsed() {
        if (this.poolSearchStartedAt === null) return '0.0';
        return ((performance.now() - this.poolSearchStartedAt) / 1000).toFixed(1);
    },

    setMinimalButtonLabel(label) {
        if (this.minimalMode) this.submitButton.textContent = label;
    },

    async startMinimalFormProof(poolWorker) {
        // The pool accepted a share. The worker that found it now solves one
        // ordinary proof for the form's token; the other workers stop.
        for (const other of this.poolSearchWorkers) {
            if (other !== poolWorker) other.worker.terminate();
        }
        this.poolSearchWorkers = [poolWorker];
        this.stopPoolSearchTimer();
        this.setMinimalButtonLabel(`Share accepted; verifying... ${this.getPoolSearchElapsed()}s`);
        try {
            const challenge = await this.issueChallenge('/forms/contact');
            if (!this.poolSearchActive) return;
            const lease = await this.requestLease(challenge.challenge_id);
            if (!this.poolSearchActive) return;
            poolWorker.worker.postMessage({
                type: 'solve',
                data: { ...lease, challenge_id: challenge.challenge_id }
            });
        } catch (error) {
            if (!this.poolSearchActive) return;
            this.finishPoolSearch('Form verification failed: ' + error.message);
        }
    },

    async handleMinimalFormProof(proof) {
        try {
            const result = await this.submitProof(proof);
            if (!this.poolSearchActive) return;
            await this.completeMinimalFormSubmission(result.token);
        } catch (error) {
            if (!this.poolSearchActive) return;
            this.finishPoolSearch('Form verification failed: ' + error.message);
        }
    },

    async completeMinimalFormSubmission(token) {
        this.stopPoolWorkers();
        this.stopPoolSearchTimer();
        this.setMinimalButtonLabel(`Submitting... ${this.getPoolSearchElapsed()}s`);
        this.setFormEnabled(false);
        try {
            await this.submitForm(token);
            const elapsed = this.getPoolSearchElapsed();
            this.stopPoolSearchTimer();
            this.poolSearchStartedAt = null;
            this.poolSearchForForm = false;
            this.pendingForm = null;
            this.pendingFormToken = null;
            this.form.reset();
            this.setFormEnabled(true);
            this.submitButton.title = '';
            this.submitButton.removeAttribute('aria-label');
            this.setMinimalButtonLabel(`Submitted in ${elapsed}s`);
        } catch (error) {
            console.error('Form submission failed after pool share acceptance:', error);
            this.pendingFormToken = token;
            this.poolSearchForForm = false;
            this.stopPoolSearchTimer();
            this.setFormEnabled(true);
            this.setMinimalButtonLabel('Retry form submission');
            this.submitButton.title = error.message;
            this.submitButton.setAttribute(
                'aria-label',
                `Form submission failed: ${error.message}. Click to retry.`
            );
        }
    },

    async retryMinimalFormSubmission() {
        this.setFormEnabled(false);
        this.setMinimalButtonLabel('Submitting form...');
        try {
            await this.submitForm(this.pendingFormToken);
            this.form.reset();
            this.pendingForm = null;
            this.pendingFormToken = null;
            this.setFormEnabled(true);
            this.submitButton.title = '';
            this.submitButton.removeAttribute('aria-label');
            this.setMinimalButtonLabel('Form submitted');
        } catch (error) {
            console.error('Form submission retry failed:', error);
            this.setFormEnabled(true);
            this.setMinimalButtonLabel('Retry form submission');
            this.submitButton.title = error.message;
            this.submitButton.setAttribute(
                'aria-label',
                `Form submission failed: ${error.message}. Click to retry.`
            );
        }
    },

    handlePoolWorkerMessage(poolWorker, event) {
        if (!this.poolSearchActive || !this.poolSearchWorkers.includes(poolWorker)) return;
        const message = event.data;
        if (message.type === 'ready') {
            if (!message.data.moduleLoaded) {
                this.finishPoolSearch(
                    'Pool search could not initialize WASM: ' +
                    (message.data.error || 'unknown error')
                );
                return;
            }
            this.requestNextPoolBatch(poolWorker);
        } else if (message.type === 'progress') {
            this.poolSearchStatus.textContent =
                `Worker ${poolWorker.index}: ${message.data.attempts.toLocaleString()} hashes in ` +
                `its current batch; ${this.poolSearchVerifiedBatches} batches verified.`;
        } else if (message.type === 'empty-batch') {
            this.requestNextPoolBatch(poolWorker);
        } else if (message.type === 'proof' && message.data.pool_search) {
            this.handlePoolBatchProof(message.data, poolWorker);
        } else if (message.type === 'proof' && this.poolSearchForForm) {
            this.handleMinimalFormProof(message.data);
        } else if (message.type === 'error') {
            // A failed batch or form proof ends the search; its text is in data.
            this.finishPoolSearch('Pool search failed: ' + message.data);
        }
    },

    stopPoolSearch() {
        if (!this.poolSearchActive) return;
        this.finishPoolSearch(
            `Pool search stopped. ${this.poolSearchVerifiedBatches} batch proofs were verified; ` +
            'no pool share was found.'
        );
    },

    async issueChallenge(resource = '/forms/contact') {
        const response = await fetch(this.serverUrl + '/api/challenge', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ resource })
        });
        if (!response.ok) throw new Error(`Challenge request failed (${response.status})`);
        return response.json();
    },

    async requestLease(challengeId) {
        const response = await fetch(this.serverUrl + '/api/lease', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ challenge_id: challengeId, worker_id: this.workerId })
        });
        if (!response.ok) throw new Error(await response.text());
        return response.json();
    },

    async submitProof(proof) {
        const response = await fetch(this.serverUrl + '/api/proof', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(proof)
        });
        if (!response.ok) throw new Error(await response.text());
        return response.json();
    },

    async submitForm(token) {
        const response = await fetch(this.serverUrl + '/api/forms/contact', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(this.pendingForm)
        });
        if (!response.ok) throw new Error(await response.text());
        return response.json();
    },

    cancelChallenge() {
        this.worker.postMessage({ type: 'cancel-solve' });
        this.pendingForm = null;
        this.panel.hidden = true;
        this.setFormEnabled(true);
        this.poolSearchButton.disabled = false;
        this.setStatus('Verification cancelled. The form was not submitted.');
        this.updateProgress(0);
        this.cancelButton.disabled = true;
    },

    handleWorkerMessage(event) {
        switch (event.data.type) {
            case 'progress': {
                const progress = event.data.data;
                this.setStatus(`Verifying proof of work... ${progress.attempts} hashes`);
                this.updateProgress(progress.percentage);
                break;
            }
            case 'proof':
                this.setStatus('Proof received; verifying it before submitting the form...');
                this.cancelButton.disabled = true;
                this.submitProof(event.data.data)
                    .then((token) => this.submitForm(token.token))
                    .then((result) => {
                        this.setStatus(result.message);
                        this.form.reset();
                        this.setFormEnabled(true);
                        this.poolSearchButton.disabled = false;
                        this.pendingForm = null;
                        this.updateProgress(100);
                    })
                    .catch((error) => {
                        console.error('Form verification failed:', error);
                        this.setStatus('Form verification failed: ' + error.message);
                        this.cancelButton.disabled = false;
                        this.poolSearchButton.disabled = false;
                    });
                break;
            case 'error':
                this.setStatus('Challenge could not be solved: ' + event.data.data);
                this.cancelButton.disabled = false;
                this.poolSearchButton.disabled = false;
                break;
        }
    },

    setStatus(message) {
        if (this.status) this.status.textContent = message;
    },

    setFormEnabled(enabled) {
        this.form.querySelectorAll('input, textarea, button[type="submit"]').forEach((control) => {
            control.disabled = !enabled;
        });
    },

    updateProgress(percentage) {
        if (this.progress) this.progress.style.width = percentage + '%';
    }
};

document.addEventListener('DOMContentLoaded', () => controller.init());
