export function selectToolCard(cards, secret) {
 return cards.filter(c=>c.secret===secret&&!c.alias_to).sort((a,b)=>Number(!b.pending&&!b.frozen)-Number(!a.pending&&!a.frozen)||Number(b.limit==null)-Number(a.limit==null)||String(b.created||"").localeCompare(String(a.created||"")))[0]||null;
}
export function toolCards(cards) {
 return [...new Set(cards.filter(c=>!c.alias_to).map(c=>c.secret))].map(secret=>({...selectToolCard(cards,secret),name:secret}));
}
export async function recentEvents(vault,prefix,limit) {
 let cursor,keys=[];
 do {const page=await vault.list({prefix,cursor});keys.push(...page.keys.map(k=>k.name));keys.sort().reverse();keys=keys.slice(0,limit);cursor=page.list_complete?undefined:page.cursor;}while(cursor);
 const events=[];for(const key of keys){const raw=await vault.get(key);if(raw){try{events.push(JSON.parse(raw));}catch{}}}return events;
}
