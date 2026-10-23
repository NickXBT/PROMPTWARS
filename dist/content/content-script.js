let h=null;function b(e){if(h||document.getElementById("phishing-shield-warning-host"))return;const t=document.createElement("div");t.id="phishing-shield-warning-host",t.style.position="fixed",t.style.top="0",t.style.left="0",t.style.width="100%",t.style.zIndex="2147483647",t.style.fontFamily='-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';const i=t.attachShadow({mode:"closed"}),o=document.createElement("style");o.textContent=`
    .ps-banner {
      background: #D93025;
      color: #FFFFFF;
      padding: 12px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      font-size: 14px;
      line-height: 1.4;
      animation: psSlideDown 0.3s ease-out;
    }
    @keyframes psSlideDown {
      from { transform: translateY(-100%); }
      to { transform: translateY(0); }
    }
    .ps-content {
      display: flex;
      align-items: center;
      gap: 14px;
      flex: 1;
    }
    .ps-icon {
      font-size: 24px;
      flex-shrink: 0;
    }
    .ps-title {
      font-weight: 700;
      font-size: 15px;
      margin-bottom: 2px;
    }
    .ps-desc {
      opacity: 0.95;
    }
    .ps-actions {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-left: 16px;
    }
    .ps-btn {
      background: #FFFFFF;
      color: #D93025;
      border: none;
      border-radius: 4px;
      padding: 6px 12px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: background 0.15s;
    }
    .ps-btn:hover {
      background: #F1F3F4;
    }
    .ps-btn-dismiss {
      background: transparent;
      color: #FFFFFF;
      border: 1px solid rgba(255, 255, 255, 0.6);
    }
    .ps-btn-dismiss:hover {
      background: rgba(255, 255, 255, 0.15);
    }
  `,i.appendChild(o);const s=document.createElement("div");s.className="ps-banner",s.setAttribute("role","alert");const n=document.createElement("div");n.className="ps-content";const d=document.createElement("div");d.className="ps-icon",d.textContent="⚠️";const c=document.createElement("div"),a=document.createElement("div");a.className="ps-title",a.textContent=`Phishing Shield AI Alert: High-Risk Website (${e.score}/100)`;const m=document.createElement("div");m.className="ps-desc",m.textContent=e.simpleExplanation,c.appendChild(a),c.appendChild(m),n.appendChild(d),n.appendChild(c);const p=document.createElement("div");p.className="ps-actions";const r=document.createElement("button");r.className="ps-btn",r.textContent="View Evidence",r.addEventListener("click",()=>{typeof chrome<"u"&&chrome.runtime?.sendMessage&&chrome.runtime.sendMessage({type:"OPEN_EVIDENCE_PANEL",result:e}),alert(`Phishing Shield AI Findings:

Score: ${e.score}/100
Verdict: ${e.verdict}

Top Reasons:
${e.reasons.slice(0,3).map((l,f)=>`${f+1}. [${l.code}] ${l.evidence}`).join(`
`)}

Recommended Action:
${e.recommendedAction}`)});const u=document.createElement("button");u.className="ps-btn ps-btn-dismiss",u.textContent="Dismiss Warning",u.addEventListener("click",()=>{w()}),p.appendChild(r),p.appendChild(u),s.appendChild(n),s.appendChild(p),i.appendChild(s),document.body.prepend(t),h=t}function w(){h&&h.parentNode&&(h.parentNode.removeChild(h),h=null)}function E(){const e=document.querySelectorAll("h1, h2, h3, p, label, .alert, .notice, .warning"),t=[];let i=0;for(let o=0;o<e.length;o++){const n=(e[o].textContent||"").trim().replace(/\s+/g," ");if(n.length>5&&n.length<500&&(t.push(n),i+=n.length,i>2e3))break}return t.join(`
`)}function C(){const e=[];return document.querySelectorAll("form").forEach(i=>{const o=i.getAttribute("action")||window.location.href;let s=!1,n=!1;try{const r=new URL(o,window.location.origin);s=r.protocol==="http:",n=r.hostname!==window.location.hostname}catch{}const d=i.querySelectorAll("input, select, textarea");let c=!1,a=!1,m=!1;const p=[];d.forEach(r=>{const u=(r.getAttribute("type")||"text").toLowerCase(),l=(r.getAttribute("name")||"").toLowerCase(),f=(r.getAttribute("id")||"").toLowerCase(),y=(r.getAttribute("autocomplete")||"").toLowerCase();p.push(u),(u==="password"||l.includes("pass")||f.includes("pass"))&&(c=!0),(l.includes("card")||l.includes("cc")||l.includes("cvv")||y.includes("cc-"))&&(a=!0),(l.includes("otp")||l.includes("2fa")||l.includes("code")||l.includes("token")||f.includes("otp"))&&(m=!0)}),e.push({action:o,method:(i.getAttribute("method")||"GET").toUpperCase(),hasPasswordInput:c,hasCreditCardInput:a,hasOtpInput:m,inputTypes:p,isCrossDomain:n,isPlainHttp:s})}),e}function A(){const e=[],t=document.querySelectorAll("a[href]"),i=window.location.hostname;return t.forEach(o=>{const s=o.getAttribute("href");if(!(!s||s.startsWith("#")||s.startsWith("javascript:")))try{const n=new URL(s,window.location.origin),d=n.hostname!==i,c=(o.textContent||"").trim();e.push({href:n.href,text:c,isExternal:d})}catch{}}),e.slice(0,40)}function v(){const e=C(),t=A(),i=E(),o=[];let s=!1;return e.forEach(n=>{o.push(...n.inputTypes),(n.hasPasswordInput||n.hasCreditCardInput||n.hasOtpInput)&&(s=!0)}),{url:window.location.href,origin:window.location.origin,hostname:window.location.hostname,pathname:window.location.pathname,title:document.title||"",textExcerpt:i,forms:e,links:t,hasSensitiveInputs:s,inputTypes:o,isEmailContext:window.location.hostname.includes("mail.google.com")}}function F(e){if(!e||e.length===0)return;const t=new Map(e.map(o=>[o.url,o]));document.querySelectorAll("a[href]").forEach(o=>{const s=o.getAttribute("href");if(!s)return;let n;try{n=new URL(s,window.location.origin).href}catch{return}const d=t.get(n);if(d){const c=o;c.style.outline="2px dashed #D93025",c.style.outlineOffset="2px",c.style.backgroundColor="rgba(217, 48, 37, 0.08)";const a=document.createElement("span");a.className="ps-suspicious-badge",a.textContent=" ⚠️ [Deceptive Link] ",a.style.fontSize="11px",a.style.color="#D93025",a.style.fontWeight="bold",a.title=d.reasons.join(" | "),c.appendChild(a)}})}function g(){const e=v();typeof chrome<"u"&&chrome.runtime?.sendMessage&&chrome.runtime.sendMessage({type:"ANALYZE_PAGE_REQUEST",payload:e},t=>{t&&t.success&&t.result&&x(t.result)})}function x(e){e.score>=60&&b(e),F(e.suspiciousUrls)}typeof chrome<"u"&&chrome.runtime?.onMessage&&chrome.runtime.onMessage.addListener((e,t,i)=>{e.type==="ANALYZE_PAGE_RESPONSE"&&e.payload&&(x(e.payload),i({received:!0})),e.type==="TRIGGER_PAGE_SCAN"&&(g(),i({started:!0}))});document.readyState==="loading"?document.addEventListener("DOMContentLoaded",g):g();
