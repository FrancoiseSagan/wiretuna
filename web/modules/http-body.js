import { el } from './dom.js';

const DECOMPRESSED_LIMIT = 1024 * 1024;
const charsets = [
  ['', '自动'], ['utf-8', 'UTF-8'], ['gb18030', 'GB18030 / GBK'],
  ['big5', 'Big5'], ['utf-16le', 'UTF-16 LE'], ['utf-16be', 'UTF-16 BE'],
];

export function bodyPanel(bytes, headers) {
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
  const note = el('p', '', 'muted');
  const text = el('pre');
  toolbar.append(label);
  panel.append(toolbar, note, text);

  const declared = declaredCharset(headers);
  async function show() {
    let decoded;
    try {
      decoded = await decompress(bytes, headers);
    } catch (error) {
      note.textContent = error.message;
      choice.disabled = true;
      return;
    }
    const render = () => {
      const charset = choice.value || declared || 'utf-8';
      let decoder;
      try {
        decoder = new TextDecoder(charset, { fatal: true });
      } catch {
        note.textContent = `无法识别字符集 ${charset}，请选择字符集。`;
        text.textContent = '';
        return;
      }
      try {
        text.textContent = decoder.decode(decoded.bytes, { stream: decoded.limited });
        note.textContent = decoded.limited
          ? `已达到 1 MiB 解压显示上限 · ${decoder.encoding}` : decoder.encoding;
      } catch {
        text.textContent = new TextDecoder(charset).decode(decoded.bytes, { stream: decoded.limited });
        note.textContent = `${decoder.encoding} 有无法解码的字节，可手动切换字符集。`;
        if (decoded.limited) note.textContent += ' 已达到 1 MiB 解压显示上限。';
      }
    };
    choice.addEventListener('change', render);
    render();
  }
  show();
  return panel;
}

function declaredCharset(headers) {
  const type = headers.find(header => header.name.toLowerCase() === 'content-type')?.value;
  const charset = type?.match(/;\s*charset\s*=\s*(?:"([^"]*)"|([^;\s]+))/i);
  return (charset?.[1] ?? charset?.[2] ?? '').trim();
}

async function decompress(bytes, headers) {
  const encodings = headers.filter(header => header.name.toLowerCase() === 'content-encoding')
    .flatMap(header => header.value.toLowerCase().split(',').map(value => value.trim()))
    .filter(value => value && value !== 'identity').reverse();
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
