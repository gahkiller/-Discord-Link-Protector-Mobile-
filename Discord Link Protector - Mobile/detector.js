/*
Enhanced detection module for Discord Link Protector.
- Categories: shortener, ip-logger, malware, phishing, giveaway/scam, token-grabber, crypto-scam, suspicious
- Heuristics: leetspeak normalization, homograph detection (basic), long query/fragment, many subdomains, obfuscated words
- Exposes:
    LinkDetector.detectText(text) => { matches: [...], score }
    LinkDetector.mergeExternalLists(obj) => merges external blocklist JSON
*/

(function(global){
  // Built-in lists (can be expanded or loaded from external JSON via mergeExternalLists)
  const LISTS = {
    shorteners: new Set([
      "bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","buff.ly","is.gd","cutt.ly","rb.gy","v.gd","bitly.com","lc.chat","shorturl.at","soo.gd","s.id","zii.li","soo.gd"
    ]),
    ip_loggers: new Set([
      "grabify.link","iplogger.org","iplogger.com","yip.su","2no.co","ipgrabber.ru","iplogger.co","ipgraber.ru","bmwforum.co","spoiler.org"
    ]),
    token_grabbers: new Set([
      // common patterns or hosts used in token grabber pages (example placeholders)
      "token-grab.net","discord-token-stealer.com","tokengrab.info"
    ]),
    known_scam_hosts: new Set([
      "free-nitro.com","discord-giveaway.com","claim-nitro.org","nitro-discord.gift",
      "discord-verify.net","discord-security.xyz","verify-discord.ga"
    ]),
    crypto_scams: new Set([
      "fakecrypto.xyz","airdrop-claim.com","crypto-giveaway.net","wallet-claim.org"
    ]),
    malware_signs: new Set([
      ".exe",".zip",".rar",".scr",".msi",".bat",".ps1",".apk",".dmg"
    ]),
    phishing_keywords: new Set([
      "login","verify","signin","claim","secure","account","password","recovery","confirm","validate"
    ]),
    giveaway_keywords: new Set([
      "free","giveaway","claim","winner","winners","nitro","gift","reward","prize"
    ])
  };

  // Config thresholds
  const CONFIG = {
    longPathLength: 180,
    manySubdomains: 3,
    longQueryLength: 200,
    suspiciousScoreThreshold: 1
  };

  // Basic leetspeak normalization map
  const LEET_MAP = { '0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','@':'a','$':'s' };

  function normalizeText(t){
    if(!t) return '';
    let s = t.toLowerCase();
    // remove zero-width chars
    s = s.replace(/[\u200B-\u200F]/g,'');
    // collapse repeated whitespace
    s = s.replace(/\s+/g,' ');
    // expand common obfuscation: replace 'dot' and '[.]' with '.'
    s = s.replace(/\[?\.\]?/g,'.');
    s = s.replace(/\bdot\b/g,'.');
    // leet normalization for letters/numbers
    s = s.split('').map(ch => LEET_MAP[ch] || ch).join('');
    return s;
  }

  function extractUrls(text){
    if(!text) return [];
    // Improved URL regex capturing protocols, www, IPs, domain-like strings and many edge cases
    const re = /((https?:\/\/)?((?:[a-z0-9-]{1,63}\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(:[0-9]{1,5})?(\/[^\s]*)?)/ig;
    const out = [];
    let m;
    while((m = re.exec(text)) !== null){
      const raw = m[0];
      let href = raw;
      if(!/^https?:\/\//i.test(href)) href = "http://" + href;
      out.push({ raw, href });
    }
    return out;
  }

  function hostnameOf(url){
    try {
      return new URL(url).hostname.replace(/^www\./,'').toLowerCase();
    } catch(e){ return ''; }
  }
  function pathOf(url){
    try { return new URL(url).pathname + (new URL(url).search||'') + (new URL(url).hash||''); } catch(e){ return ''; }
  }

  function countSubdomains(host){
    if(!host) return 0;
    return host.split('.').length - 2; // exclude domain + tld approx
  }

  // Basic homograph-ish detection: presence of unicode letters outside ASCII (simple signal)
  function hasUnicodeHomograph(s){
    return /[^\x00-\x7F]/.test(s);
  }

  function hasMalwareHint(path){
    if(!path) return false;
    for(const ext of LISTS.malware_signs) if(path.toLowerCase().includes(ext)) return true;
    return false;
  }

  function hostInSet(host, set){
    if(!host) return false;
    if(set.has(host)) return true;
    // check subdomains: e.g., sub.bit.ly
    const parts = host.split('.');
    for(let i=0;i<parts.length-1;i++){
      const candidate = parts.slice(i).join('.');
      if(set.has(candidate)) return true;
    }
    return false;
  }

  // Heuristic: suspicious query params often used in redirects/phishing (utm is benign)
  function suspiciousQuery(url){
    try{
      const u = new URL(url);
      const qs = u.searchParams;
      if(!qs) return false;
      let suspiciousCount = 0;
      for(const [k,v] of qs){
        const key = k.toLowerCase();
        const val = (v||'').toLowerCase();
        if(key.includes('token') || key.includes('auth') || key.includes('session') || key.includes('pass') || key.includes('password')) suspiciousCount++;
        if(val && (val.length>200 || val.match(/^[a-z0-9]{40,}$/))) suspiciousCount++;
      }
      return suspiciousCount>0;
    } catch(e){
      return false;
    }
  }

  // Main detection
  function analyzeUrl(rawUrl, surroundingTextNorm){
    const host = hostnameOf(rawUrl);
    const path = pathOf(rawUrl);
    const result = { url: rawUrl, host, path, categories: [], reasons: [], confidence: 0 };

    if(!host) return null;

    // Exact lists
    if(hostInSet(host, LISTS.shorteners)){ result.categories.push('shortener'); result.reasons.push('URL shortener'); result.confidence+=2; }
    if(hostInSet(host, LISTS.ip_loggers)){ result.categories.push('ip-logger'); result.reasons.push('IP logger / tracker'); result.confidence+=3; }
    if(hostInSet(host, LISTS.token_grabbers)){ result.categories.push('token-grabber'); result.reasons.push('Known token grabber host'); result.confidence+=4; }
    if(hostInSet(host, LISTS.known_scam_hosts)){ result.categories.push('scam-host'); result.reasons.push('Known scam host'); result.confidence+=4; }
    if(hostInSet(host, LISTS.crypto_scams)){ result.categories.push('crypto-scam'); result.reasons.push('Known crypto scam host'); result.confidence+=3; }

    // Malware hints
    if(hasMalwareHint(path)){ result.categories.push('malware'); result.reasons.push('Suspicious file extension'); result.confidence+=3; }

    // Keywords in surrounding normalized text
    if(surroundingTextNorm){
      for(const kw of LISTS.giveaway_keywords){
        if(surroundingTextNorm.includes(kw)){ result.categories.push('giveaway'); result.reasons.push('Giveaway/reward keyword'); result.confidence+=1; break; }
      }
      for(const kw of LISTS.phishing_keywords){
        if(surroundingTextNorm.includes(kw)){ result.categories.push('phishing-like'); result.reasons.push('Phishing-like keyword'); result.confidence+=1; break; }
      }
      if(surroundingTextNorm.match(/(free nitro|free nitro|nitro for free|claim nitro|discord nitro)/)) {
        result.categories.push('nitro-scam'); result.reasons.push('Nitro giveaway phrasing'); result.confidence+=2;
      }
      if(surroundingTextNorm.match(/(wallet|airdrop|private key|seed phrase|phrase)/)) {
        result.categories.push('crypto-phish'); result.reasons.push('Crypto phishing phrasing'); result.confidence+=3;
      }
    }

    // Heuristics
    if(countSubdomains(host) >= CONFIG.manySubdomains){ result.categories.push('many-subdomains'); result.reasons.push('Many subdomains'); result.confidence+=1; }
    if(path.length >= CONFIG.longPathLength){ result.categories.push('long-path'); result.reasons.push('Very long path'); result.confidence+=1; }
    if(path.length >= CONFIG.longQueryLength){ result.categories.push('long-query'); result.reasons.push('Long query/fragment'); result.confidence+=1; }
    if(suspiciousQuery(rawUrl)){ result.categories.push('suspicious-query'); result.reasons.push('Suspicious query parameters'); result.confidence+=2; }
    if(hasUnicodeHomograph(host)){ result.categories.push('homograph'); result.reasons.push('Possible homograph/unicode domain'); result.confidence+=2; }

    // Obfuscated text matching: check if normalized surrounding text contains obfuscated scam keywords
    if(surroundingTextNorm){
      const obf = surroundingTextNorm.replace(/[^a-z0-9]/g,'');
      if(obf.match(/freenitro|claimnitro|getnitro|freemoney|buyback|giveaway|prize/)){
        result.categories.push('obfuscated-scam'); result.reasons.push('Obfuscated scam keyword'); result.confidence+=2;
      }
    }

    // If none matched but host looks weird (TLD-like numeric IP or long random host)
    if(!result.categories.length){
      const hostParts = host.split('.');
      const tld = hostParts[hostParts.length-1] || '';
      if(/^\d+$/.test(tld) || host.length > 60 || host.match(/[a-z0-9]{20,}/)){
        result.categories.push('suspicious'); result.reasons.push('Suspicious host pattern'); result.confidence+=1;
      }
    }

    return result;
  }

  function detectText(text){
    const norm = normalizeText(text);
    const urls = extractUrls(text);
    const matches = [];
    for(const u of urls){
      const a = analyzeUrl(u.href, norm);
      if(a){
        // post-process: derive overall category labels
        if(a.confidence >= 4) a.severity = 'high';
        else if(a.confidence >= 2) a.severity = 'medium';
        else a.severity = 'low';
        // only include if confidence above minimal threshold OR category from lists
        if(a.confidence >= CONFIG.suspiciousScoreThreshold || a.categories.length){
          matches.push(a);
        }
      }
    }
    return { matches, score: matches.reduce((s,m)=>s+m.confidence,0) };
  }

  // Allow merging external JSON lists into LISTS at runtime
  function mergeExternalLists(obj){
    if(!obj || typeof obj !== 'object') return;
    for(const key of Object.keys(obj)){
      if(!LISTS[key]) LISTS[key] = new Set();
      const arr = Array.isArray(obj[key]) ? obj[key] : [];
      arr.forEach(x => { if(x && typeof x === 'string') LISTS[key].add(x.toLowerCase()); });
    }
  }

  // Expose
  global.LinkDetector = { detectText, mergeExternalLists, _LISTS: LISTS };
})(window);
