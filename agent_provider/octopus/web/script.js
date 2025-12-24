// Octopus AI Assistant - Frontend JavaScript

class OctopusChat {
    constructor() {
        this.elements = {
            chatMessages: document.getElementById('chatMessages'),
            messageInput: document.getElementById('messageInput'),
            imageInput: document.getElementById('imageInput'),
            addImageButton: document.getElementById('addImageButton'),
            imageFileName: document.getElementById('imageFileName'),
            imagePreview: document.getElementById('imagePreview'),
            sendButton: document.getElementById('sendButton'),
            characterCount: document.getElementById('characterCount'),
            statusIndicator: document.getElementById('statusIndicator'),
            targetHost: document.getElementById('targetHost'),
            gatewayUrl: document.getElementById('gatewayUrl'),
            modeRadios: Array.from(document.querySelectorAll('input[name="mode"]')),
            consentModal: document.getElementById('consentModal'),
            consentDid: document.getElementById('consentDid'),
            consentMethod: document.getElementById('consentMethod'),
            consentParams: document.getElementById('consentParams'),
            consentAccept: document.getElementById('consentAccept'),
            consentReject: document.getElementById('consentReject'),
            sidebar: document.getElementById('sidebar'),
            sidebarToggle: document.getElementById('sidebarToggle'),
            sidebarClose: document.getElementById('sidebarClose'),
            anpSettings: document.getElementById('anpSettings'),
        };
        this.allowSpeech = false;

        this.isLoading = false;
        this.maxCharacters = 2000;

        this.pendingConsent = null;
        this.consentPollTimer = null;
        this.consentEmptyPolls = 0;
        this.consentMaxEmptyPolls = 2;

        this.init();
    }

    init() {
        this.bindEvents();
        this.updateCharacterCount();
        this.checkSystemStatus();

        // Auto-resize textarea
        this.autoResizeTextarea();

        // Start consent polling
        this.startConsentPolling();
    }

    bindEvents() {
        // Send button click
        this.elements.sendButton.addEventListener('click', () => {
            this.sendMessage();
        });

        // Enter key to send (Shift+Enter for new line)
        this.elements.messageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Character count update
        this.elements.messageInput.addEventListener('input', () => {
            this.updateCharacterCount();
            this.autoResizeTextarea();
        });

        // Paste event handling
        this.elements.messageInput.addEventListener('paste', (e) => {
            setTimeout(() => {
                this.updateCharacterCount();
                this.autoResizeTextarea();
            }, 10);
        });

        if (this.elements.addImageButton) {
            this.elements.addImageButton.addEventListener('click', () => {
                if (!this.elements.imageInput) return;
                try {
                    if (typeof this.elements.imageInput.showPicker === 'function') {
                        this.elements.imageInput.showPicker();
                    } else {
                        this.elements.imageInput.click();
                    }
                } catch (_) {
                    this.elements.imageInput.click();
                }
            });
        }

        if (this.elements.imageInput) {
            this.elements.imageInput.addEventListener('change', () => {
                const file = this.elements.imageInput.files && this.elements.imageInput.files[0] ? this.elements.imageInput.files[0] : null;
                if (file) {
                    if (this.elements.imageFileName) this.elements.imageFileName.textContent = `选择图片：${file.name}`;
                    this.renderImagePreview(file);
                    this.showNotification('图片已选择', 'success');
                } else {
                    if (this.elements.imageFileName) this.elements.imageFileName.textContent = '';
                    this.clearImagePreview();
                }
                this.updateCharacterCount();
            });
        }

        if (this.elements.modeRadios && this.elements.modeRadios.length) {
            this.elements.modeRadios.forEach(r => r.addEventListener('change', () => {
                const mode = this.getMode();
                this.showNotification(mode === 'local' ? '已切换到本地模式' : '已切换到 ANP 通信模式', 'info');
                
                // Toggle ANP settings visibility
                if (this.elements.anpSettings) {
                    if (mode === 'anp') {
                        this.elements.anpSettings.classList.remove('hidden');
                    } else {
                        this.elements.anpSettings.classList.add('hidden');
                    }
                }
            }));
        }

        // Consent actions
        if (this.elements.consentAccept) {
            this.elements.consentAccept.addEventListener('click', () => this.respondConsent(true));
        }
        if (this.elements.consentReject) {
            this.elements.consentReject.addEventListener('click', () => this.respondConsent(false));
        }

        // Sidebar events
        if (this.elements.sidebarToggle) {
            this.elements.sidebarToggle.addEventListener('click', () => {
                this.elements.sidebar.classList.add('open');
            });
        }
        if (this.elements.sidebarClose) {
            this.elements.sidebarClose.addEventListener('click', () => {
                this.elements.sidebar.classList.remove('open');
            });
        }
        // Close sidebar when clicking outside
        document.addEventListener('click', (e) => {
            if (this.elements.sidebar && 
                this.elements.sidebar.classList.contains('open') && 
                !this.elements.sidebar.contains(e.target) && 
                !this.elements.sidebarToggle.contains(e.target)) {
                this.elements.sidebar.classList.remove('open');
            }
        });
    }

    autoResizeTextarea() {
        const textarea = this.elements.messageInput;
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
    }

    async startConsentPolling() {
        const poll = async () => {
            try {
                const res = await fetch('/consent/pending');
                const data = await res.json();
                const pending = (data && data.pending) || [];
                if (!this.pendingConsent && pending.length > 0) {
                    this.pendingConsent = pending[0];
                    this.showConsent(this.pendingConsent);
                    if (this.consentPollTimer) {
                        clearInterval(this.consentPollTimer);
                        this.consentPollTimer = null;
                    }
                    this.consentEmptyPolls = 0;
                } else if (pending.length === 0) {
                    this.consentEmptyPolls += 1;
                    if (this.consentPollTimer && this.consentEmptyPolls >= this.consentMaxEmptyPolls) {
                        clearInterval(this.consentPollTimer);
                        this.consentPollTimer = null;
                    }
                }
            } catch (_) {}
        };
        // poll every 1s
        this.consentPollTimer = setInterval(poll, 1000);
        poll();
    }

    stopConsentPolling() {
        if (this.consentPollTimer) {
            clearInterval(this.consentPollTimer);
            this.consentPollTimer = null;
        }
    }

    showConsent(item) {
        if (!item) return;
        this.elements.consentDid.textContent = `请求方 DID：${item.did || '-'}`;
        this.elements.consentMethod.textContent = `调用方法：${item.method}`;
        this.elements.consentParams.textContent = JSON.stringify(item.params || {}, null, 2);
        this.elements.consentModal.classList.remove('hidden');
    }

    async respondConsent(accept) {
        if (!this.pendingConsent) return;
        try {
            const resp = await fetch('/consent/decide', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ request_id: this.pendingConsent.request_id, decision: accept ? 'accept' : 'reject' })
            });
            if (!resp.ok) {
                this.showNotification(`授权操作失败: ${resp.status}`, 'error');
                return;
            }
            const data = await resp.json();
            if (data && data.success) {
                this.showNotification(accept ? '已接受请求' : '已拒绝请求', accept ? 'success' : 'warning');
                const acceptedItem = this.pendingConsent; // capture before reset
                this.elements.consentModal.classList.add('hidden');
                this.stopConsentPolling();

                if (accept) {
                    const origin = data.origin_host || '未知来源';
                    const reqText = data.request_text || (acceptedItem?.params?.request) || '';
                    this.addMessage(`接收来自${origin}的请求 “${reqText}”`, 'user');
                    const rid = data.request_id || (acceptedItem && acceptedItem.request_id) || null;
                    if (rid) this.pollConsentResult(rid);
                }

                this.pendingConsent = null;
                return;
            }
            this.showNotification('授权接口返回异常', 'error');
        } catch (_) {}
    }

    async pollConsentResult(requestId) {
        if (!requestId) return;
        let resultShown = false;

        const check = async () => {
            try {
                const res = await fetch(`/consent/status?request_id=${encodeURIComponent(requestId)}`);
                if (!res.ok) return null;
                const info = await res.json();
                return info;
            } catch (_) {
                return null;
            }
        };

        const showIfReady = async () => {
            const info = await check();
            if (!info) return false;
            if (info.status === 'completed' && info.result && !resultShown) {
                this.addMessage(info.result, 'assistant');
                resultShown = true;
                return true;
            }
            return false;
        };

        const initialDone = await showIfReady();
        if (initialDone) return;

        const timer = setInterval(async () => {
            const done = await showIfReady();
            if (done) clearInterval(timer);
        }, 500);
    }

    updateCharacterCount() {
        const currentLength = this.elements.messageInput.value.length;
        this.elements.characterCount.textContent = `${currentLength}/${this.maxCharacters}`;

        const hasImage = this.elements.imageInput && this.elements.imageInput.files && this.elements.imageInput.files.length > 0;
        const isEmpty = (currentLength === 0) && !hasImage;
        const tooLong = currentLength > this.maxCharacters;

        this.elements.sendButton.disabled = isEmpty || tooLong || this.isLoading;

        // Update character count color
        if (tooLong) {
            this.elements.characterCount.style.color = '#dc2626';
        } else if (currentLength > this.maxCharacters * 0.9) {
            this.elements.characterCount.style.color = '#f59e0b';
        } else {
            this.elements.characterCount.style.color = '#94a3b8';
        }
    }

    async checkSystemStatus() {
        try {
            const response = await fetch('/v1/status');
            const data = await response.json();

            if (data.status === 'healthy') {
                this.updateStatus('Ready', 'success');
            } else {
                this.updateStatus('System Issue', 'error');
            }
        } catch (error) {
            console.error('Status check failed:', error);
            this.updateStatus('Disconnected', 'error');
        }

        // Gate image upload by backend UI config
        try {
            const r2 = await fetch('/v1/ui-config');
            const cfg = await r2.json();
            const allowImage = !!(cfg && cfg.allow_image_input);
            this.allowSpeech = !!(cfg && cfg.allow_speech_output);
            const theme = (cfg && cfg.theme) ? String(cfg.theme) : 'purple';
            this.applyTheme(theme);
            if (!allowImage) {
                if (this.elements.addImageButton) this.elements.addImageButton.style.display = 'none';
                if (this.elements.imageInput) this.elements.imageInput.disabled = true;
                if (this.elements.imagePreview) this.elements.imagePreview.style.display = 'none';
                if (this.elements.imageFileName) this.elements.imageFileName.textContent = '';
            }
        } catch (e) {}
    }

    applyTheme(theme) {
        const headerMap = {
            'purple': ['#6a11cb', '#a4508b'],
            'blue': ['#4facfe', '#00f2fe'],
            'pink': ['#ff758c', '#ff7eb3'],
            'green': ['#34d399', '#059669']
        };
        const bodyMap = {
            'purple': ['#e9d5ff', '#d8b4fe'],
            'blue': ['#bfdbfe', '#93c5fd'],
            'pink': ['#ffd1dc', '#ff9bb3'],
            'green': ['#bbf7d0', '#86efac']
        };
        const headerPair = headerMap[theme] || headerMap['purple'];
        const bodyPair = bodyMap[theme] || bodyMap['purple'];
        document.documentElement.style.setProperty('--accent-start', headerPair[0]);
        document.documentElement.style.setProperty('--accent-end', headerPair[1]);
        try {
            const headerGrad = `linear-gradient(135deg, ${headerPair[0]} 0%, ${headerPair[1]} 100%)`;
            const bodyGrad = `linear-gradient(135deg, ${bodyPair[0]} 0%, ${bodyPair[1]} 100%)`;
            const header = document.querySelector('.header');
            if (header) header.style.background = headerGrad;
            document.body.style.background = bodyGrad;
        } catch (_) {}
    }

    updateStatus(text, type) {
        const statusText = this.elements.statusIndicator.querySelector('.status-text');
        const statusDot = this.elements.statusIndicator.querySelector('.status-dot');

        statusText.textContent = text;

        // Remove existing status classes
        statusDot.classList.remove('status-success', 'status-error', 'status-warning');

        // Add appropriate status class
        switch (type) {
            case 'success':
                statusDot.style.background = '#4ade80';
                break;
            case 'error':
                statusDot.style.background = '#ef4444';
                break;
            case 'warning':
                statusDot.style.background = '#f59e0b';
                break;
            default:
                statusDot.style.background = '#94a3b8';
        }
    }

    async sendMessage() {
        const messageText = this.elements.messageInput.value.trim();
        const imageFile = this.elements.imageInput && this.elements.imageInput.files && this.elements.imageInput.files[0] ? this.elements.imageInput.files[0] : null;

        if ((!messageText && !imageFile) || this.isLoading) {
            return;
        }

        // Add user message to chat (attach selected image if any)
        this.addMessage(messageText, 'user', 'normal', imageFile ? (this.currentImagePreviewUrl || URL.createObjectURL(imageFile)) : null);

        // Clear input
        this.elements.messageInput.value = '';
        this.updateCharacterCount();
        this.autoResizeTextarea();

        // Show loading state (add processing message)
        const processingMessageId = this.addProcessingMessage();
        this.setLoading(true);

        try {
            let response;
            const mode = this.getMode();

            if (mode === 'anp') {
                const targetHost = (this.elements.targetHost?.value || '127.0.0.1:9529').trim();
                const gatewayUrl = (this.elements.gatewayUrl?.value || '').trim();
                response = await fetch('/v1/chat/anp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message: messageText,
                        target_host: targetHost,
                        gateway_url: gatewayUrl || undefined,
                        origin_host: window.location.host
                    })
                });
            } else {
                if (imageFile) {
                    const fd = new FormData();
                    fd.append('prompt', messageText || '');
                    fd.append('image', imageFile);
                    response = await fetch('/v1/vision', { method: 'POST', body: fd });
                } else {
                    response = await fetch('/v1/chat', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ message: messageText, timestamp: new Date().toISOString() })
                    });
                }
            }

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            // Remove processing message
            this.removeProcessingMessage(processingMessageId);

            if (data.success) {
                let respText = data.response;
                try {
                    const obj = JSON.parse(data.response);
                    if (obj && (obj.ocr_text || obj.answer)) {
                        const ocr = obj.ocr_text ? String(obj.ocr_text).trim() : '';
                        const ans = obj.answer ? String(obj.answer).trim() : '';
                        respText = (ocr ? `识别文字：\n${ocr}\n\n` : '') + (ans ? `答案：\n${ans}` : '');
                    }
                } catch (_) {}
                this.addMessage(respText, 'assistant', 'normal', imageFile ? (this.currentImagePreviewUrl || null) : null);
                this.updateStatus('Ready', 'success');
                if (this.elements.imageInput) this.elements.imageInput.value = '';
                this.clearImagePreview();
                if (this.elements.imageFileName) this.elements.imageFileName.textContent = '';
                this.updateCharacterCount();
            } else {
                // Handle error response
                this.addMessage(
                    `抱歉，处理您的请求时遇到了问题：${data.error || '未知错误'}`,
                    'assistant',
                    'error'
                );
                this.updateStatus('Error', 'error');
            }

        } catch (error) {
            console.error('Send message error:', error);

            // Remove processing message
            this.removeProcessingMessage(processingMessageId);

            this.addMessage(
                '抱歉，网络连接出现问题，请稍后重试。',
                'assistant',
                'error'
            );
            this.updateStatus('Connection Error', 'error');
        } finally {
            this.setLoading(false);
        }
    }

    addMessage(content, sender, type = 'normal', imageUrl = null) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${sender}-message`;

        const avatarDiv = document.createElement('div');
        avatarDiv.className = 'message-avatar';
        avatarDiv.innerHTML = sender === 'user' ? '👤' : '🤖';

        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';

        // Handle different message types
        if (type === 'error') {
            contentDiv.classList.add('error-message');
        }

        // Format content (handle JSON responses, code blocks, etc.)
        const formattedContent = this.formatMessageContent(content);
        contentDiv.innerHTML = formattedContent;
        if (sender === 'assistant' && this.allowSpeech) {
            const playBtn = document.createElement('button');
            playBtn.className = 'add-image-button';
            playBtn.title = '朗读';
            playBtn.textContent = '🔊';
            playBtn.addEventListener('click', async () => {
                try {
                    const r = await fetch('/v1/tts', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ text: content })
                    });
                    const j = await r.json();
                    if (j && j.success && j.url) {
                        const audio = new Audio(j.url);
                        audio.play();
                    }
                } catch (_) {}
            });
            contentDiv.appendChild(playBtn);
        }

        // Optional image attachment under text
        if (imageUrl) {
            const img = document.createElement('img');
            img.src = imageUrl;
            img.alt = '附件图片';
            img.className = 'message-image';
            contentDiv.appendChild(img);
        }

        messageDiv.appendChild(avatarDiv);
        messageDiv.appendChild(contentDiv);

        this.elements.chatMessages.appendChild(messageDiv);

        // Scroll to bottom
        this.scrollToBottom();
    }

    formatMessageContent(content) {
        // Handle JSON responses
        try {
            const parsed = JSON.parse(content);
            if (typeof parsed === 'object') {
                const wr = parsed && parsed.weather_results && Array.isArray(parsed.weather_results) ? parsed.weather_results[0] : null;
                const now = wr && wr.now ? wr.now : null;
                if (now) {
                    const parts = [];
                    if (now.text) parts.push(now.text);
                    if (now.temp) parts.push(`${now.temp}°C`);
                    if (now.feelsLike) parts.push(`体感${now.feelsLike}°C`);
                    const wind = [now.windDir, now.windSpeed].filter(Boolean).join(' ');
                    if (wind) parts.push(`风：${wind}`);
                    if (now.humidity) parts.push(`湿度${now.humidity}%`);
                    if (now.pressure) parts.push(`气压${now.pressure}hPa`);
                    if (now.vis) parts.push(`能见度${now.vis}km`);
                    const summary = `天气：${parts.join('，')}`;
                    const link = wr && wr.fxLink ? `<a href="${wr.fxLink}" target="_blank" rel="noopener noreferrer">查看详情</a>` : '';
                    return `<p>${summary}${link ? ' · ' + link : ''}</p>`;
                }
                return `<pre>${JSON.stringify(parsed, null, 2)}</pre>`;
            }
        } catch (e) {
            // Not JSON, continue with regular formatting
        }

        // Convert line breaks to HTML
        let formatted = content.replace(/\n/g, '<br>');

        // Handle code blocks (```code```)
        formatted = formatted.replace(/```([\s\S]*?)```/g, '<pre>$1</pre>');

        // Handle inline code (`code`)
        formatted = formatted.replace(/`([^`]+)`/g, '<code style="background: rgba(0,0,0,0.1); padding: 0.2rem 0.4rem; border-radius: 0.25rem; font-family: monospace;">$1</code>');

        return `<p>${formatted}</p>`;
    }

    addProcessingMessage() {
        // Generate unique ID for processing message
        const processingId = 'processing_' + Date.now();

        const messageDiv = document.createElement('div');
        messageDiv.className = 'message assistant-message processing-message';
        messageDiv.id = processingId;

        const avatarDiv = document.createElement('div');
        avatarDiv.className = 'message-avatar';
        avatarDiv.innerHTML = '🤖';

        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content processing-content';
        contentDiv.innerHTML = `
            <div class="processing-indicator">
                <div class="typing-dots">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
                <p>AI正在思考中...</p>
            </div>
        `;

        messageDiv.appendChild(avatarDiv);
        messageDiv.appendChild(contentDiv);

        this.elements.chatMessages.appendChild(messageDiv);

        // Scroll to bottom
        this.scrollToBottom();

        return processingId;
    }

    removeProcessingMessage(processingId) {
        const processingMessage = document.getElementById(processingId);
        if (processingMessage) {
            processingMessage.remove();
        }
    }

    setLoading(loading) {
        this.isLoading = loading;

        if (loading) {
            this.updateStatus('Processing...', 'warning');
        }

        this.elements.sendButton.disabled = loading;
        this.updateCharacterCount();
    }

    scrollToBottom() {
        this.elements.chatMessages.scrollTop = this.elements.chatMessages.scrollHeight;
    }

    renderImagePreview(file) {
        const preview = this.elements.imagePreview;
        if (!preview || !file) return;
        const url = URL.createObjectURL(file);
        this.currentImagePreviewUrl = url;
        const img = document.createElement('img');
        img.src = url;
        const name = document.createElement('span');
        name.className = 'name';
        name.textContent = file.name || 'image';
        preview.innerHTML = '';
        preview.appendChild(img);
        preview.appendChild(name);
        preview.style.display = 'flex';
    }

    clearImagePreview() {
        const preview = this.elements.imagePreview;
        if (!preview) return;
        preview.innerHTML = '';
        preview.style.display = 'none';
        if (this.currentImagePreviewUrl) {
            try { URL.revokeObjectURL(this.currentImagePreviewUrl); } catch (_) {}
            this.currentImagePreviewUrl = null;
        }
    }

    // Utility method to show notifications
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;

        // Style the notification
        Object.assign(notification.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            padding: '1rem 1.5rem',
            borderRadius: '0.5rem',
            color: 'white',
            fontWeight: '500',
            zIndex: '9999',
            opacity: '0',
            transform: 'translateX(100%)',
            transition: 'all 0.3s ease'
        });

        // Set background color based on type
        switch (type) {
            case 'success':
                notification.style.background = '#10b981';
                break;
            case 'error':
                notification.style.background = '#ef4444';
                break;
            case 'warning':
                notification.style.background = '#f59e0b';
                break;
            default:
                notification.style.background = '#6366f1';
        }

        document.body.appendChild(notification);

        // Animate in
        setTimeout(() => {
            notification.style.opacity = '1';
            notification.style.transform = 'translateX(0)';
        }, 100);

        // Remove after 3 seconds
        setTimeout(() => {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }

    getMode() {
        const checked = this.elements.modeRadios ? this.elements.modeRadios.find(r => r.checked) : null;
        return checked ? checked.value : 'local';
    }
}

// Ensure theme is applied on initial load even before class initialization completes
try {
  fetch('/v1/ui-config').then(r=>r.json()).then(cfg=>{
    const map = {
      'purple': ['#6a11cb', '#a4508b'],
      'blue': ['#4facfe', '#00f2fe'],
      'pink': ['#ff758c', '#ff7eb3'],
      'green': ['#34d399', '#059669']
    };
    const pair = map[(cfg && cfg.theme) ? String(cfg.theme) : 'purple'] || map['purple'];
    document.documentElement.style.setProperty('--accent-start', pair[0]);
    document.documentElement.style.setProperty('--accent-end', pair[1]);
  }).catch(()=>{});
} catch (_) {}

// Initialize the chat when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.octopusChat = new OctopusChat();

    // Global error handler
    window.addEventListener('error', (event) => {
        console.error('Global error:', event.error);
    });

    // Handle unhandled promise rejections
    window.addEventListener('unhandledrejection', (event) => {
        console.error('Unhandled promise rejection:', event.reason);
    });
});
