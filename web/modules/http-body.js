import { el } from './dom.js';

const PREVIEW_BYTES = 256;
const DECOMPRESSED_LIMIT = 1024 * 1024;
const charsets = [
  ['', '自动'], ['utf-8', 'UTF-8'], ['gb18030', 'GB18030 / GBK'],
  ['big5', 'Big5'], ['utf-16le', 'UTF-16 LE'], ['utf-16be', 'UTF-16 BE'],
];

export function bodyPanel(message, loadBody) {
  const panel = el('section', '', 'http-body');
  const toolbar = el('div', '', 'sub-toolbar');
  const label = el('label', '字符集');
  const choice = el('select');
  choice.setAttribute('aria-label', '正文字符集');
  for (const [value, name] of charsets) {
    const option = el('option', name);
    option.value = value;
    choice.append(option);
  }
  label.append(choice);
  const toggle = el('button', '查看完整正文');
  toggle.type = 'button';
  toggle.setAttribute('aria-expanded', 'false');
  const note = el('p', '', 'muted');
  const text = el('pre');
  toolbar.append(label, toggle);
  panel.append(toolbar, note, text);

  const declared = declaredCharset(message.headers);
  const encodings = contentEncodings(message.headers);
  const preview = new Uint8Array(message.preview);
  let full = null;
  let expanded = false;

  function render() {
    const bytes = full?.bytes ?? preview;
    const displayed = expanded ? bytes : bytes.subarray(0, PREVIEW_BYTES);
    const hasMore = full ? bytes.length > PREVIEW_BYTES : preview.length < message.body_bytes;
    toggle.hidden = !expanded && !hasMore;
    toggle.textContent = expanded ? '收起正文' : '查看完整正文';
    toggle.setAttribute('aria-expanded', String(expanded));

    const clipped = !expanded && hasMore;
    const caption = clipped ? '正文开头' : '正文';
    const limit = full?.limited && expanded ? ' · 已达到 1 MiB 解压显示上限' : '';
    const charset = choice.value || declared || 'utf-8';
    let decoder;
    try {
      decoder = new TextDecoder(charset, { fatal: true });
    } catch {
      note.textContent = `无法识别字符集 ${charset}，请选择字符集。`;
      text.textContent = '';
      return;
    }
    const options = { stream: clipped || Boolean(full?.limited) };
    try {
      text.textContent = decoder.decode(displayed, options);
      note.textContent = `${caption} · ${decoder.encoding}${limit}`;
    } catch {
      text.textContent = new TextDecoder(charset).decode(displayed, options);
      note.textContent = `${caption} · ${decoder.encoding} 有无法解码的字节，可手动切换字符集。${limit}`;
    }
  }

  async function loadFull() {
    toggle.disabled = true;
    try {
      full = await decompress(await loadBody(), encodings);
      return true;
    } catch (error) {
      note.textContent = error.message;
      return false;
    } finally {
      toggle.disabled = false;
    }
  }

  choice.addEventListener('change', render);
  toggle.addEventListener('click', async () => {
    if (!expanded && !full && !(await loadFull())) return;
    expanded = !expanded;
    render();
  });

  if (encodings.length) {
    toggle.hidden = true;
    choice.disabled = true;
    note.textContent = '正在解压正文开头…';
    loadFull().then(loaded => {
      if (loaded) {
        choice.disabled = false;
        render();
      }
    });
  } else {
    if (preview.length >= message.body_bytes) full = { bytes: preview, limited: false };
    render();
  }
  return panel;
}

function declaredCharset(headers) {
  const type = headers.find(header => header.name.toLowerCase() === 'content-type')?.value;
  const charset = type?.match(/;\s*charset\s*=\s*(?:"([^"]*)"|([^;\s]+))/i);
  return (charset?.[1] ?? charset?.[2] ?? '').trim();
}

function contentEncodings(headers) {
  return headers.filter(header => header.name.toLowerCase() === 'content-encoding')
    .flatMap(header => header.value.toLowerCase().split(',').map(value => value.trim()))
    .filter(value => value && value !== 'identity').reverse();
}

async function decompress(bytes, encodings) {
  if (encodings.length > 4) throw new Error('正文压缩层数超过显示上限。');
  let result = { bytes, limited: false };
  for (const [index, encoding] of encodings.entries()) {
    const format = { gzip: 'gzip', 'x-gzip': 'gzip', deflate: 'deflate', br: 'brotli' }[encoding];
    let decoder;
    try {
      if (typeof format !== 'string') throw new Error();
      decoder = new DecompressionStream(format);
    } catch {
      throw new Error(`浏览器无法解压 ${encoding} 正文。`);
    }
    const stream = new Blob([result.bytes]).stream().pipeThrough(decoder);
    try {
      result = await readBounded(stream);
    } catch {
      throw new Error(`${encoding} 正文解压失败。请检查捕获是否完整。`);
    }
    if (result.limited && index < encodings.length - 1) {
      throw new Error('中间解压结果超过 1 MiB，无法继续解压。');
    }
  }
  return result;
}

async function readBounded(stream) {
  const reader = stream.getReader();
  const parts = [];
  let length = 0;
  let limited = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.length > DECOMPRESSED_LIMIT - length) {
        parts.push(value.slice(0, DECOMPRESSED_LIMIT - length));
        length = DECOMPRESSED_LIMIT;
        limited = true;
        await reader.cancel();
        break;
      }
      parts.push(value);
      length += value.length;
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return { bytes, limited };
}
