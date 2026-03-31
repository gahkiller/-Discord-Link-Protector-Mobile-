// Simple storage API for blocked links and dynamic list updates.
const DEFAULT_STATE = {
  blocked: {},
  blocklistVersion: 1
};

function getState() {
  return new Promise((res) => {
    chrome.storage.local.get(DEFAULT_STATE, (s) => res(s));
  });
}

function setState(obj) {
  return new Promise((res) => {
    chrome.storage.local.set(obj, () => res());
  });
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg && msg.type === 'getState') {
    getState().then(reply);
    return true;
  }
  if (msg && msg.type === 'blockLink') {
    getState().then((s) => {
      s.blocked = s.blocked || {};
      s.blocked[msg.url] = { time: Date.now(), reason: msg.reason || 'user' };
      chrome.storage.local.set({ blocked: s.blocked });
      reply({ ok: true });
    });
    return true;
  }
  if (msg && msg.type === 'unblockLink') {
    getState().then((s) => {
      s.blocked = s.blocked || {};
      delete s.blocked[msg.url];
      chrome.storage.local.set({ blocked: s.blocked });
      reply({ ok: true });
    });
    return true;
  }
});
