// Scanner shield: spots probing (SQL injection strings, hidden-file hunts, scanner tools), wastes the prober's time with
// slow, identical, empty answers, and locks the address out. Real users never trip it. Defensive only: nothing is sent back.
const PATH = /(\.(env|git|svn|hg|bak|old|sql|swp|zip|tar|gz|rar|7z|php\d?|aspx?|jsp|cgi|pem|key|ini|log)(\/|$)|\/\.(aws|ssh|docker|htaccess|htpasswd)|wp-(admin|login|content|includes|json)|phpmyadmin|xmlrpc|actuator|server-status|etc\/passwd|id_rsa|web-inf|\/cgi-bin|boaform|vendor\/phpunit|\/(adminer|manager\/html|solr|console|debug|telescope|_profiler)\b)/i;
const PAYLOAD = /(union(\s|\+|%20|\/\*.*?\*\/)+(all(\s|\+|%20)+)?select|information_schema|sleep\s*\(\s*\d|benchmark\s*\(|waitfor\s+delay|pg_sleep|load_file\s*\(|into\s+outfile|'\s*or\s*'?\d+'?\s*=\s*'?\d|"\s*or\s*"?\d+"?\s*=|;\s*drop\s+table|<script|javascript:|onerror\s*=|onload\s*=|\.\.(\/|%2f|\\|%5c)|%2e%2e|\$\{jndi:|\$\(|\|\s*(cat|ls|id|whoami)\b|\bxp_cmdshell|\/bin\/(ba)?sh)/i;
const UA = /(sqlmap|nikto|nmap|masscan|nuclei|acunetix|wpscan|zgrab|dirbuster|gobuster|ffuf|feroxbuster|havij|netsparker|openvas|w3af|arachni|burpcollaborator|jaeles|dalfox|wfuzz|hydra)/i;
const strikes = new Map(), log = [];
const sleep = ms => new Promise(r => setTimeout(r, ms));
function dec(s) { try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch (e) { return String(s); } }
function reason(path, query, body, ua) {
  if (UA.test(ua || '')) return 'scanner tool';
  if (PATH.test(dec(path))) return 'probe path';
  if (PAYLOAD.test(dec(path)) || PAYLOAD.test(dec(typeof query === 'string' ? query : JSON.stringify(query || {})))) return 'attack string';
  if (body && body.length < 20000 && PAYLOAD.test(dec(body))) return 'attack string in body';
  return null;
}
// returns null for normal traffic, or a ready response for a prober
async function check(ip, path, query, body, ua) {
  const now = Date.now(), s = strikes.get(ip) || { n: 0, until: 0, at: now };
  if (strikes.size > 5000) strikes.clear();
  const why = s.until > now ? 'locked out' : reason(path, query, body, ua);
  if (!why) return null;
  if (why !== 'locked out') { s.n++; s.at = now; if (s.n >= 3) s.until = now + 6 * 3600e3 * Math.pow(2, Math.min(5, s.n - 3)); /* 6h to 7d */ strikes.set(ip, s); log.unshift({ at: new Date(now).toISOString(), ip: String(ip).slice(0, 45), why, path: String(path).slice(0, 120) }); log.length = Math.min(log.length, 100); }
  else strikes.set(ip, s);
  await sleep(Math.min(25000, 2500 * Math.pow(2, Math.min(4, s.n))) + Math.floor(Math.random() * 2500)); /* longer each strike */   // the time sink
  return { status: 404, headers: { 'content-type': 'application/json' }, body: '{"error":"Not found"}' };   // always the same, so probing teaches nothing
}
module.exports = { check, log: () => log.slice(0, 50) };
