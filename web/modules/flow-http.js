import { json, query, request } from './api.js';
import { byId, el } from './dom.js';
import { bodyPanel } from './http-body.js';

export class HttpView {
  constructor({ onError, onPacket }) {
    this.onError = onError;
    this.onPacket = onPacket;
    this.messages = byId('http-messages');
    this.detail = byId('http-detail');
    this.serial = 0;
    this.detailSerial = 0;
    byId('http-filter').addEventListener('submit', event => {
      event.preventDefault();
      this.filters = {
        method: byId('http-method').value.trim(),
        status: byId('http-status').value,
      };
      this.load(0, true);
    });
    byId('http-prev').addEventListener('click', () => this.load(this.history.pop() ?? 0));
    byId('http-next').addEventListener('click', () => {
      this.history.push(this.offset);
      this.load(this.cursor);
    });
  }

  setFlow(path) {
    this.path = path;
    this.filters = {};
    byId('http-method').value = '';
    byId('http-status').value = '';
    this.load(0, true);
  }

  reset() {
    this.path = null;
    this.serial++;
    this.detailSerial++;
  }

  refresh() {
    if (this.path) return this.load(this.offset ?? 0);
  }

  async load(offset, reset = false) {
    if (!this.path) return;
    if (reset) this.history = [];
    const serial = ++this.serial;
    this.detailSerial++;
    this.detail.replaceChildren(el('p', '选择一个请求或响应。', 'muted'));
    this.offset = offset;
    try {
      const result = await json(`${this.path}/http?${query({ ...this.filters, offset })}`);
      if (serial !== this.serial) return;
      byId('http-note').textContent = result.note ?? '';
      byId('http-prev').disabled = this.history.length === 0;
      byId('http-next').disabled = !result.more;
      byId('http-offset').textContent = `本页 ${result.transactions.length} 个事务`;
      this.cursor = result.next;
      this.messages.replaceChildren(...result.transactions.map(transaction => {
        const row = el('div', '', 'http-transaction');
        if (transaction.request) row.append(this.button(transaction.request));
        row.append(...transaction.responses.map(response => this.button(response)));
        if (!transaction.responses.length) row.append(el('span', '尚未观察到响应', 'muted'));
        if (transaction.response_ms != null) row.append(el('span', `请求到响应 ${transaction.response_ms.toFixed(2)} ms`, 'muted'));
        return row;
      }));
      if (!result.transactions.length) this.messages.append(el('p', '当前流中没有匹配的明文 HTTP/1.1 消息。', 'empty'));
    } catch (error) {
      if (serial === this.serial) this.onError(error.message);
    }
  }

  button(message) {
    const button = el('button', caption(message), message.status == null ? '' : 'http-response');
    button.type = 'button';
    button.addEventListener('click', () => this.select(message.id));
    return button;
  }

  async select(id) {
    const serial = ++this.detailSerial;
    try {
      const path = `${this.path}/http/${id}`;
      const message = await json(path);
      if (serial !== this.detailSerial) return;
      const title = el('strong', caption(message));
      const source = el('button', `来源包 #${message.first_packet}`, 'plain');
      source.type = 'button';
      source.addEventListener('click', () => this.onPacket(message.first_packet));
      const headers = el('dl');
      for (const header of message.headers) {
        const row = el('div');
        row.append(el('dt', header.name), el('dd', header.value));
        headers.append(row);
      }
      const summary = el('p', `已捕获正文 ${message.body_bytes} B`, 'muted');
      this.detail.replaceChildren(title, source, headers, summary);
      if (message.issue) this.detail.append(el('p', message.issue, 'sub-note'));
      if (message.body_bytes > 0) {
        this.detail.append(bodyPanel(message, async () => {
          const response = await request(`${path}/body`);
          return new Uint8Array(await response.arrayBuffer());
        }));
      }
    } catch (error) {
      if (serial === this.detailSerial) this.onError(error.message);
    }
  }
}

function caption(message) {
  return message.status == null ? `${message.method} ${message.target}` : `HTTP ${message.status}`;
}
