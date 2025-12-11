// Chat Manager
window.ChatManager = (function () {
    const socket = window.socket;
    let elements = {};

    function init() {
        elements = {
            messages: document.getElementById('chat-messages'),
            input: document.getElementById('chat-input')
        };

        if (!elements.input || !elements.messages) {
            console.error('Chat elements not found');
            return;
        }

        elements.input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && elements.input.value.trim()) {
                sendMessage(elements.input.value.trim());
                elements.input.value = '';
            }
        });

        socket.on('chat_message', (data) => {
            appendMessage(data);
        });
    }

    function sendMessage(message) {
        socket.emit('chat_message', { message: message });
    }

    function appendMessage(data) {
        const isSelf = data.username === state.username;
        const msgEl = document.createElement('div');
        msgEl.className = `message ${isSelf ? 'self' : ''}`;
        msgEl.innerHTML = `
            <div class="message-header">
                <span class="username">${data.username}</span>
                <span class="time">${new Date(data.timestamp).toLocaleTimeString()}</span>
            </div>
            <div class="message-content">${escapeHtml(data.message)}</div>
        `;
        elements.messages.appendChild(msgEl);
        elements.messages.scrollTop = elements.messages.scrollHeight;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', init);

    return {};
})();
