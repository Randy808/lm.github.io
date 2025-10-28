import { LiquidSDK } from './sdk.js';

const sdk = new LiquidSDK();

let state = {
  userAddress: '',
  balance: 0,
  chats: {},
  currentPubKey: null,
  messageCost: 1000
};

function generateQRCode(text, canvas) {
  const ctx = canvas.getContext('2d');
  const size = 256;
  const qrSize = 29;
  const cellSize = size / qrSize;

  canvas.width = size;
  canvas.height = size;

  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, size, size);

  const matrix = generateQRMatrix(text, qrSize);

  ctx.fillStyle = '#000000';
  for (let row = 0; row < qrSize; row++) {
    for (let col = 0; col < qrSize; col++) {
      if (matrix[row][col]) {
        ctx.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
      }
    }
  }
}

function generateQRMatrix(text, size) {
  const matrix = Array(size).fill(null).map(() => Array(size).fill(false));

  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    hash = ((hash << 5) - hash) + text.charCodeAt(i);
    hash = hash & hash;
  }

  const random = (seed) => {
    const x = Math.sin(seed++) * 10000;
    return x - Math.floor(x);
  };

  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      const seed = hash + row * size + col;
      matrix[row][col] = random(seed) > 0.5;
    }
  }

  for (let i = 0; i < 7; i++) {
    for (let j = 0; j < 7; j++) {
      if (i === 0 || i === 6 || j === 0 || j === 6 || (i >= 2 && i <= 4 && j >= 2 && j <= 4)) {
        matrix[i][j] = true;
        matrix[i][size - 1 - j] = true;
        matrix[size - 1 - i][j] = true;
      } else {
        matrix[i][j] = false;
        matrix[i][size - 1 - j] = false;
        matrix[size - 1 - i][j] = false;
      }
    }
  }

  return matrix;
}

function formatTime(timestamp) {
  const date = typeof timestamp === 'number' ? new Date(timestamp * 1000) : new Date(timestamp);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function truncatePubKey(address) {
  if (!address) return '';
  if (address.length <= 20) return address;
  return `${address.slice(0, 12)}...${address.slice(-8)}`;
}

function truncateAddress(address) {
  if (!address) return '';
  if (address.length <= 20) return address;
  return `${address.slice(0, 12)}...${address.slice(-8)}`;
}

function renderChatList() {
  const chatList = document.getElementById('chat-list');
  chatList.innerHTML = '';

  const pubKeys = Object.keys(state.chats);

  if (pubKeys.length === 0) {
    chatList.innerHTML = '<div class="empty-state">No conversations yet</div>';
    return;
  }

  pubKeys.forEach(pubKey => {
    const chat = state.chats[pubKey];
    const lastMessage = chat.messages[chat.messages.length - 1];

    const chatItem = document.createElement('div');
    chatItem.className = `chat-item ${state.currentPubKey === pubKey ? 'active' : ''}`;
    chatItem.onclick = () => selectChat(pubKey);

    chatItem.innerHTML = `
      <div class="chat-item-header">
        <div class="chat-pubkey">${truncatePubKey(pubKey)}</div>
        ${lastMessage ? `<div class="chat-time">${formatTime(lastMessage.timestamp)}</div>` : ''}
      </div>
      ${lastMessage ? `<div class="chat-preview">${lastMessage.text}</div>` : '<div class="chat-preview">No messages yet</div>'}
    `;

    chatList.appendChild(chatItem);
  });
}

function renderMessages() {
  const container = document.getElementById('messages-container');
  container.innerHTML = '';

  if (!state.currentPubKey) {
    container.innerHTML = '<div class="empty-state">Select a conversation to start messaging</div>';
    return;
  }

  const chat = state.chats[state.currentPubKey];
  if (!chat || chat.messages.length === 0) {
    container.innerHTML = '<div class="empty-state">No messages yet. Start the conversation!</div>';
    return;
  }

  chat.messages.forEach(msg => {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${msg.sender}`;

    const explorerLink = msg.explorerUrl
      ? `<a href="${msg.explorerUrl}" target="_blank" rel="noopener noreferrer" class="explorer-link">
           <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
             <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
             <polyline points="15 3 21 3 21 9"></polyline>
             <line x1="10" y1="14" x2="21" y2="3"></line>
           </svg>
           View
         </a>`
      : '';

    messageDiv.innerHTML = `
      <div class="message-content">
        <div class="message-text">${msg.text}</div>
        <div class="message-footer">
          <div class="message-time">${formatTime(msg.timestamp)}</div>
          ${explorerLink}
        </div>
      </div>
    `;

    container.appendChild(messageDiv);
  });

  container.scrollTop = container.scrollHeight;
}

function selectChat(pubKey) {
  state.currentPubKey = pubKey;

  document.getElementById('chat-pubkey').textContent = truncatePubKey(pubKey);

  renderChatList();
  renderMessages();
}

function createNewChat(pubKey) {
  if (!pubKey || state.chats[pubKey]) {
    return;
  }

  state.chats[pubKey] = {
    messages: []
  };

  selectChat(pubKey);
  renderChatList();
}

async function sendMessage(text) {
  if (!state.currentPubKey || !text.trim()) {
    return;
  }

  if (state.balance < state.messageCost) {
    alert('Insufficient balance to send message');
    return;
  }

  const unixTimestamp = Math.floor(Date.now() / 1000);

  state.chats[state.currentPubKey].messages.push({
    text: text.trim(),
    sender: 'user',
    timestamp: unixTimestamp,
    isMine: true
  });

  state.balance -= state.messageCost;
  document.getElementById('user-balance').textContent = `${state.balance.toLocaleString()} sats`;

  renderMessages();
  renderChatList();

  try {
    debugger;
    await sendBitcoin(state.currentPubKey, text);
  } catch (error) {
    console.error('Failed to send message:', error);
  }
}

async function loadMessagesFromSDK() {
  try {
    const messagesData = await showMessages(0);

    Object.entries(messagesData).forEach(([pubKey, messages]) => {
      if (!state.chats[pubKey]) {
        state.chats[pubKey] = { messages: [] };
      }

      messages.forEach(msg => {
        state.chats[pubKey].messages.push({
          text: msg.message,
          sender: msg.is_mine ? 'user' : 'other',
          timestamp: msg.confirmation_time,
          explorerUrl: msg.explorer_url || null,
          isMine: msg.is_mine
        });
      });
    });

    renderChatList();

    if (!state.currentPubKey && Object.keys(state.chats).length > 0) {
      selectChat(Object.keys(state.chats)[0]);
    }
  } catch (error) {
    console.error('Failed to load messages:', error);
  }
}

async function initializeApp() {
  try {
    state.userAddress = await getConfidentialAddress();
    document.getElementById('user-address').textContent = truncateAddress(state.userAddress);
    document.getElementById('modal-address').textContent = state.userAddress;

    state.balance = await getBalance();
    document.getElementById('user-balance').textContent = `${state.balance.toLocaleString()} sats`;

    await loadMessagesFromSDK();

    const receiveBtn = document.getElementById('receive-btn');
    const receiveModal = document.getElementById('receive-modal');
    const closeReceiveModal = document.getElementById('close-receive-modal');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const copyAddressBtn = document.getElementById('copy-address-btn');

    receiveBtn.onclick = () => {
      receiveModal.classList.remove('hidden');
      const canvas = document.getElementById('qr-canvas');
      generateQRCode(state.userAddress, canvas);
    };

    closeReceiveModal.onclick = () => receiveModal.classList.add('hidden');
    closeModalBtn.onclick = () => receiveModal.classList.add('hidden');

    copyAddressBtn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(state.userAddress);
        const copyText = document.getElementById('copy-text');
        copyText.textContent = 'Copied!';
        setTimeout(() => {
          copyText.textContent = 'Copy';
        }, 2000);
      } catch (error) {
        console.error('Failed to copy:', error);
      }
    };

    const copyHeaderAddressBtn = document.getElementById('copy-header-address');
    copyHeaderAddressBtn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(state.userAddress);
        const originalHTML = copyHeaderAddressBtn.innerHTML;
        copyHeaderAddressBtn.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        `;
        setTimeout(() => {
          copyHeaderAddressBtn.innerHTML = originalHTML;
        }, 2000);
      } catch (error) {
        console.error('Failed to copy:', error);
      }
    };

    const newChatBtn = document.getElementById('new-chat-btn');
    const newChatModal = document.getElementById('new-chat-modal');
    const closeNewChatModal = document.getElementById('close-new-chat-modal');
    const cancelNewChatBtn = document.getElementById('cancel-new-chat-btn');
    const createChatBtn = document.getElementById('create-chat-btn');
    const newChatPubkeyInput = document.getElementById('new-chat-pubkey');

    newChatBtn.onclick = () => {
      newChatModal.classList.remove('hidden');
      newChatPubkeyInput.value = '';
      newChatPubkeyInput.focus();
    };

    closeNewChatModal.onclick = () => newChatModal.classList.add('hidden');
    cancelNewChatBtn.onclick = () => newChatModal.classList.add('hidden');

    createChatBtn.onclick = () => {
      const pubKey = newChatPubkeyInput.value.trim();
      if (pubKey) {
        createNewChat(pubKey);
        newChatModal.classList.add('hidden');
      }
    };

    newChatPubkeyInput.onkeypress = (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        createChatBtn.click();
      }
    };

    const messageForm = document.getElementById('message-form');
    const messageInput = document.getElementById('message-input');

    messageForm.onsubmit = async (e) => {
      e.preventDefault();
      const text = messageInput.value;
      if (text.trim()) {
        await sendMessage(text);
        messageInput.value = '';
      }
    };

    receiveModal.onclick = (e) => {
      if (e.target === receiveModal) {
        receiveModal.classList.add('hidden');
      }
    };

    newChatModal.onclick = (e) => {
      if (e.target === newChatModal) {
        newChatModal.classList.add('hidden');
      }
    };

  } catch (error) {
    console.error('Failed to initialize app:', error);
  }
}

initializeApp();
