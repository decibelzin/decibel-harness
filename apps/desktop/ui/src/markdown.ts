// Markdown rendering for assistant messages: parse with `marked`, hard-sanitize
// with DOMPurify (the webview runs with app privileges, so untrusted model / tool
// text must never inject script or navigation), and syntax-highlight code blocks
// with a curated highlight.js language set. Highlight colors come from CSS vars
// in App.css, so they follow the light/dark theme.

import DOMPurify from 'dompurify'
import hljs from 'highlight.js/lib/core'
import bash from 'highlight.js/lib/languages/bash'
import javascript from 'highlight.js/lib/languages/javascript'
import json from 'highlight.js/lib/languages/json'
import plaintext from 'highlight.js/lib/languages/plaintext'
import python from 'highlight.js/lib/languages/python'
import sql from 'highlight.js/lib/languages/sql'
import xml from 'highlight.js/lib/languages/xml'
import { marked } from 'marked'

for (const [name, lang] of [
  ['bash', bash],
  ['javascript', javascript],
  ['json', json],
  ['plaintext', plaintext],
  ['python', python],
  ['sql', sql],
  ['xml', xml],
] as const) {
  hljs.registerLanguage(name, lang)
}
// Common aliases the model emits.
hljs.registerAliases(['sh', 'shell', 'console', 'zsh'], { languageName: 'bash' })
hljs.registerAliases(['js', 'ts', 'typescript'], { languageName: 'javascript' })
hljs.registerAliases(['html', 'xhtml', 'http'], { languageName: 'xml' })
hljs.registerAliases(['py'], { languageName: 'python' })
hljs.registerAliases(['text', 'txt', ''], { languageName: 'plaintext' })

marked.setOptions({ gfm: true, breaks: false })

/** Parse markdown to sanitized HTML. Raw HTML in the source is escaped by the
 * sanitizer; only a safe formatting/code/table/link subset survives. */
export function renderMarkdown(src: string): string {
  const html = marked.parse(src ?? '', { async: false }) as string
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: [
      'p', 'br', 'hr', 'strong', 'em', 'del', 'code', 'pre', 'blockquote',
      'ul', 'ol', 'li', 'a', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'table', 'thead', 'tbody', 'tr', 'th', 'td', 'span',
    ],
    ALLOWED_ATTR: ['href', 'class'],
    ALLOW_DATA_ATTR: false,
  })
}

/** Syntax-highlight every `<pre><code>` in a freshly-rendered container. Safe to
 * call repeatedly because each render replaces the code elements. */
export function highlightWithin(el: Element): void {
  el.querySelectorAll('pre code').forEach((block) => {
    const lang = [...block.classList].find((c) => c.startsWith('language-'))?.slice(9)
    const code = block.textContent ?? ''
    try {
      const res = lang && hljs.getLanguage(lang)
        ? hljs.highlight(code, { language: lang })
        : hljs.highlightAuto(code)
      block.innerHTML = res.value
      block.classList.add('hljs')
    } catch {
      /* leave the code as escaped plain text if highlighting throws */
    }
  })
}
