import { json, query, request } from './api.js';
import { byId, el } from './dom.js';

export class StreamView {
  constructor({ onError, onPacket }) {
    this.onError = onError;
    this.onPacket = onPacket;
    this.direction = byId('stream-direction');
    this.format = byId('stream-format');
    this.rows = byId('stream-segments');
    this.serial = 0;
    this.bytesSerial = 0;
    this.direction.addEventListener('change', () => this.load(0, true));
    this.format.addEventListener('change', () => this.renderBytes());
    byId('stream-prev').addEventListener('click', () => this.load(this.history.pop() ?? 0));
    byId('stream-next').addEventListener('click', () => {
      this.history.push(this.offset);
      this.load(this.cursor);
    });
  }

  setFlow(path, flow) {
    this.path = path;
    this.direction.replaceChildren(...flow.endpoints.map((endpoint, index) => {
      const side = index === 0 ? 'A' : 'B';
      const option = el('option', `${side} · ${endpoint}`);
      option.value = index.toString();
      return option;
    }));
    if (flow.initiator != null) this.direction.value = flow.initiator.toString();
    this.load(0, true);
  }

  refresh() {
    if (this.path) return this.load(this.offset ?? 0);
  }

  reset() {
    this.path = null;
    this.serial++;
    this.bytesSerial++;
  }

  async load(offset, reset = false) {
    if (!this.path) return;
    if (reset) this.history = [];
    const serial = ++this.serial;
    this.bytesSerial++;
    this.data = null;
    this.renderBytes();
    this.offset = offset;
    const direction = this.direction.value;
    try {
      const page = await json(`${this.path}/segments?${query({ direction, offset })}`);
      if (serial !== this.serial) return;
      this.cursor = page.cursor;
      byId('stream-prev').disabled = this.history.length === 0;
      byId('stream-next').disabled = !page.more;
      byId('stream-offset').textContent = `${offset}–${page.cursor} / ${page.observed_end} B`;
      const notes = [];
      if (page.overlap_conflict) notes.push('重叠区间存在不同字节。');
      if (page.limited) notes.push('流已达到保留上限。');
      byId('stream-note').textContent = notes.join(' ');
      this.rows.replaceChildren(...page.segments.map(segment => this.row(segment)));
      if (!page.segments.length) this.rows.append(el('p', '此方向尚无有效载荷。', 'empty'));
      const first = page.segments.find(segment => segment.kind === 'data');
      if (first) await this.loadBytes(first.offset);
    } catch (error) {
      if (serial === this.serial) this.onError(error.message);
    }
  }

  row(segment) {
    const row = el('div', '', 'segment');
    const text = `${segment.offset} · ${segment.length} B`;
    if (segment.kind === 'gap') {
      row.append(el('span', `缺口 ${text}`, 'gap'));
      return row;
    }
    const bytes = el('button', text);
    bytes.type = 'button';
    bytes.addEventListener('click', () => this.loadBytes(segment.offset));
    const source = el('button', `来源包 #${segment.packet_id}`, 'plain');
    source.type = 'button';
    source.addEventListener('click', () => this.onPacket(segment.packet_id));
    row.append(bytes, source);
    return row;
  }

  async loadBytes(offset) {
    const serial = ++this.bytesSerial;
    try {
      const parameters = query({ direction: this.direction.value, offset, limit: 4096 });
      const response = await request(`${this.path}/bytes?${parameters}`);
      const data = new Uint8Array(await response.arrayBuffer());
      if (serial !== this.bytesSerial) return;
      this.data = data;
      this.dataOffset = offset;
      this.renderBytes();
    } catch (error) {
      if (serial === this.bytesSerial) this.onError(error.message);
    }
  }

  renderBytes() {
    byId('stream-bytes-title').textContent = this.data ? `重组字节 · 偏移 ${this.dataOffset}` : '重组字节';
    byId('stream-bytes').textContent = !this.data ? '选择一个字节区间。'
      : this.format.value === 'hex' ? hex(this.data, BigInt(this.dataOffset))
      : new TextDecoder().decode(this.data);
  }
}

function hex(bytes, offset) {
  const lines = [];
  for (let start = 0; start < bytes.length; start += 16) {
    const data = bytes.slice(start, start + 16);
    const codes = [...data].map(byte => byte.toString(16).padStart(2, '0')).join(' ');
    const ascii = [...data].map(byte => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '·').join('');
    lines.push(`${(offset + BigInt(start)).toString(16).padStart(6, '0')}  ${codes.padEnd(47)}  ${ascii}`);
  }
  return lines.join('\n');
}
