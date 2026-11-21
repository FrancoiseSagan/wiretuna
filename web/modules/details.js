import { json, query, request, sessionPath } from './api.js';
import { byId, el } from './dom.js';

const BYTE_PAGE = 256;

export class PacketDetails {
  constructor(onError) {
    this.onError = onError;
    this.serial = 0;
    this.byteSerial = 0;
    this.body = byId('protocol-detail');
    byId('packet-flow').addEventListener('click', () => {
      if (this.packet?.flow_id) this.onFlow?.(this.packet.flow_id);
    });
    this.hex = byId('hex');
    this.offset = 0;
    byId('hex-prev').addEventListener('click', () => this.loadBytes(this.offset - BYTE_PAGE));
    byId('hex-next').addEventListener('click', () => this.loadBytes(this.offset + BYTE_PAGE));
  }

  clear() {
    this.serial++;
    this.byteSerial++;
    this.packet = null;
    this.highlight = null;
    this.body.replaceChildren('选择一个数据包以查看字段。');
    this.body.classList.add('empty');
    this.hex.replaceChildren(el('span', '选择数据包后显示。', 'muted'));
    byId('selected-id').textContent = '';
    byId('packet-flow').hidden = true;
    byId('byte-count').textContent = '';
    byId('hex-range').textContent = '';
    byId('hex-prev').disabled = true;
    byId('hex-next').disabled = true;
  }

  async select(session, id) {
    this.clear();
    const serial = this.serial;
    this.base = sessionPath(session, `/packets/${id}`);
    try {
      const packet = await json(this.base);
      if (serial !== this.serial) return;
      this.packet = packet;
      this.renderFields();
      await this.loadBytes(0);
    } catch (error) {
      if (serial === this.serial) this.onError(error.message);
    }
  }

  renderFields() {
    const packet = this.packet;
    byId('selected-id').textContent = `#${packet.id}`;
    byId('packet-flow').hidden = packet.flow_id == null;
    byId('packet-flow').textContent = `查看连接 #${packet.flow_id ?? ''}`;
    byId('byte-count').textContent = `${packet.captured_len} B`;
    this.body.classList.remove('empty');
    const fragment = document.createDocumentFragment();
    if (packet.issue) fragment.append(el('p', packet.issue, 'detail-issue'));
    for (const layer of packet.layers) {
      const group = el('details', '', 'layer');
      group.open = true;
      group.append(el('summary', layer.name));
      for (const field of layer.fields) {
        const button = el('button', '', 'field');
        button.type = 'button';
        button.setAttribute('aria-pressed', 'false');
        button.append(el('span', field.key), el('span', field.value));
        button.addEventListener('click', () => {
          this.body.querySelector('[aria-pressed="true"]')?.setAttribute('aria-pressed', 'false');
          button.setAttribute('aria-pressed', 'true');
          this.highlight = [field.offset, field.offset + field.length];
          this.loadBytes(Math.floor(field.offset / BYTE_PAGE) * BYTE_PAGE);
        });
        group.append(button);
      }
      fragment.append(group);
    }
    this.body.replaceChildren(fragment);
  }

  async loadBytes(offset) {
    const packet = this.packet;
    if (!packet) return;
    const serial = ++this.byteSerial;
    this.offset = Math.max(0, offset);
    const parameters = query({ offset: this.offset, limit: BYTE_PAGE });
    try {
      const response = await request(`${this.base}/bytes?${parameters}`);
      const data = new Uint8Array(await response.arrayBuffer());
      if (serial !== this.byteSerial) return;
      this.renderBytes(data);
    } catch (error) {
      if (serial === this.byteSerial) this.onError(error.message);
    }
  }

  renderBytes(bytes) {
    const fragment = document.createDocumentFragment();
    for (let start = 0; start < bytes.length; start += 16) {
      fragment.append(el('span', `${(this.offset + start).toString(16).padStart(6, '0')}  `, 'hex-offset'));
      const line = bytes.slice(start, start + 16);
      const ascii = el('span', '', 'hex-ascii');
      for (const [index, byte] of line.entries()) {
        const absolute = this.offset + start + index;
        const marked = this.highlight && absolute >= this.highlight[0] && absolute < this.highlight[1];
        const hex = byte.toString(16).padStart(2, '0');
        const character = byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '·';
        fragment.append(marked ? el('mark', hex) : hex, ' ');
        ascii.append(marked ? el('mark', character) : character);
      }
      fragment.append(' '.repeat((16 - line.length) * 3 + 1), ascii, '\n');
    }
    this.hex.replaceChildren(fragment);
    const end = this.offset + bytes.length;
    byId('hex-range').textContent = bytes.length ? `${this.offset}–${end - 1} / ${this.packet.captured_len}` : '0 字节';
    byId('hex-prev').disabled = this.offset === 0;
    byId('hex-next').disabled = end >= this.packet.captured_len;
  }
}
