// Runs in Discord web client pages. Watches DOM for new messages and flags suspicious links.

const WARNING_CLASS = 'dlp-warning';
const BUTTON_CLASS = 'dlp-btn';

function createWarningNode(text, url, reason){
  const wrapper = document.createElement('span');
  wrapper.className = 'dlp-warning';
  wrapper.dataset.url = url;

  const linkEl = document.createElement('a');
  linkEl.href = url;
  linkEl.textContent = text;
  linkEl.target = '_blank';
  linkEl.rel = 'noopener noreferrer';
  linkEl.className = 'dlp-link';

  const badge = document.createElement('span');
  badge.className = 'dlp-badge';
  badge.textContent = '⚠';

  const btn = document.createElement('button');
  btn.className = BUTTON_CLASS;
  btn.textContent = 'Block';
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    chrome.runtime.sendMessage({ type: 'blockLink', url, reason }, () => {
      btn.textContent = 'Blocked';
      btn.disabled = true;
      wrapper.classList.add('dlp-blocked');
    });
  });

  const info = document.createElement('span');
  info.className = 'dlp-reason';
  info.textContent = reason || '';

  wrapper.appendChild(badge);
  wrapper.appendChild(linkEl);
  wrapper.appendChild(info);
  wrapper.appendChild(btn);
  return wrapper;
}

function replaceLinkNode(aNode, url, reason){
  // Replace text node or anchor with our warning node
  const text = aNode.textContent || url;
  const warn = createWarningNode(text, url, reason);
  aNode.parentNode && aNode.parentNode.replaceChild(warn, aNode);
}

function scanMessageNode(msgNode){
  if(!msgNode) return;
  const text = msgNode.innerText || msgNode.textContent || '';
  const res = window.LinkDetector.detectText(text);
  if(res && res.matches && res.matches.length){
    // For each match, find anchor or text and replace
    res.matches.forEach(m => {
      // Try to find anchor elements with that href
      const anchors = Array.from(msgNode.querySelectorAll('a')).filter(a => {
        try { return a.href && a.href.includes(new URL(m.url).hostname); } catch(e){ return false; }
      });
      if(anchors.length){
        anchors.forEach(a => replaceLinkNode(a, m.url, m.reason.join('; ')));
      } else {
        // try to replace text nodes containing the raw url
        const walker = document.createTreeWalker(msgNode, NodeFilter.SHOW_TEXT, null, false);
        let tn;
        while((tn = walker.nextNode())){
          if(tn.nodeValue && tn.nodeValue.includes(m.raw)){
            const span = document.createElement('span');
            span.textContent = m.raw;
            replaceLinkNode(span, m.url, m.reason.join('; '));
            break;
          }
        }
      }
    });
  }
}

function scanExistingMessages(){
  // Discord message containers: look for message content elements
  const selectors = [
    '[data-list-item-id^="chat-messages"]',
    '.message-2qnXI6',
    '.markup-eYLPri'
  ];
  const nodes = document.querySelectorAll(selectors.join(','));
  nodes.forEach(n => scanMessageNode(n));
}

const mo = new MutationObserver((mutations) => {
  for(const m of mutations){
    if(m.type === 'childList' && m.addedNodes.length){
      m.addedNodes.forEach(n => {
        if(n.nodeType !== 1) return;
        // scan for message content inside added node
        const msgEls = n.querySelectorAll ? n.querySelectorAll('.markup-eYLPri, .messageContent-2t3eCI') : [];
        if(msgEls.length){
          msgEls.forEach(me => scanMessageNode(me));
        } else {
          // maybe the node itself is a message
          if(n.matches && (n.matches('.markup-eYLPri') || n.matches('.message-2qnXI6'))){
            scanMessageNode(n);
          }
        }
      });
    }
  }
});

function startObserving(){
  const target = document.body;
  if(!target) return;
  mo.observe(target, { childList: true, subtree: true });
  // initial scan
  setTimeout(scanExistingMessages, 1500);
}

startObserving();
window.addEventListener('load', () => setTimeout(startObserving, 1000));
