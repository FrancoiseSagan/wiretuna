import { json, query, sessionPath } from './api.js';
import { byId, el, utc } from './dom.js';
import { HttpView } from './flow-http.js';
import { StreamView } from './flow-stream.js';

const PAGE_SIZE = 100;
const states = {
  handshake: '握手中', established: '已建立', observed: '中途捕获',
  'half closed': '半关闭', closed: '已关闭', reset: '已重置',
};

export class FlowList {
  constructor({ onError, onPacket, onPacketFilter }) {
    this.onError = onError;
    this.onPacketFilter = onPacketFilter;
    this.stream = new StreamView({ onError, onPacket });
    this.http = new HttpView({ onError, onPacket });
    this.rows = byId('flow-list');
    this.serial = 0;
    this.selection = 0;
    this.status = null;
    this.view = 'stream';
    byId('flow-refresh').addEventListener('click', () => this.load(this.initial(), true));
    byId('flow-prev').addEventListener('click', () => {
      const fallback = BigInt(this.start) - BigInt(PAGE_SIZE);
      this.load(this.history.pop() ?? (fallback > 0n ? fallback : 0n));
    });
    byId('flow-next').addEventListener('click', () => {
      this.history.push(this.start);
      this.load(this.cursor);
    });
    byId('show-stream').addEventListener('click', () => this.show('stream'));
    byId('show-http').addEventListener('click', () => this.show('http'));
    byId('flow-packets').addEventListener('click', () => {
      if (this.selected) this.onPacketFilter(this.selected);
    });
    byId('refresh-detail').addEventListener('click', () => this.select(this.selected));
  }

  setStatus(status) {
    const changed = this.status?.id !== status?.id;
    const updated = this.status?.newest_flow !== status?.newest_flow;
    this.status = status;
    if (changed) {
      this.serial++;
      this.clearSelection();
      this.rows.replaceChildren();
      byId('flow-empty').hidden = false;
      byId('flow-count').textContent = '';
      byId('flow-prev').disabled = true;
      byId('flow-next').disabled = true;
    }
    if ((changed || updated) && this.active) this.load(this.initial(), true);
  }

  activate(active) {
    this.active = active;
    if (active) this.load(this.initial(), true);
  }

  initial() {
    const newest = BigInt(this.status?.newest_flow ?? 0);
    return newest > BigInt(PAGE_SIZE) ? newest - BigInt(PAGE_SIZE) : 0n;
  }

  clearSelection() {
    this.selection++;
    this.selected = null;
    this.flow = null;
    this.stream.reset();
    this.http.reset();
    byId('flow-packets').hidden = true;
    byId('flow-prompt').hidden = false;
    byId('flow-details').hidden = true;
    byId('flow-caption').textContent = '';
  }

  async load(after, reset = false) {
    if (reset) this.history = [];
    if (!this.status) return;
    const serial = ++this.serial;
    try {
      const result = await json(sessionPath(this.status.id, `/flows?${query({ after, limit: PAGE_SIZE })}`));
      if (serial !== this.serial) return;
      this.start = after;
      this.cursor = result.cursor;
      byId('flow-prev').disabled = BigInt(after) === 0n;
      byId('flow-next').disabled = !result.more;
      byId('flow-count').textContent = `本页 ${result.flows.length} 条 · 共保留 ${this.status.flows} 条`;
      byId('flow-empty').hidden = result.flows.length > 0;
      this.rows.replaceChildren(...result.flows.map(flow => this.row(flow)));
    } catch (error) {
      if (serial === this.serial) this.onError(error.message);
    }
  }

  row(flow) {
    const row = el('tr');
    row.dataset.id = flow.id;
    row.tabIndex = 0;
    row.setAttribute('aria-selected', String(this.selected === flow.id));
    const packets = BigInt(flow.directions[0].packets) + BigInt(flow.directions[1].packets);
    const bytes = BigInt(flow.directions[0].bytes) + BigInt(flow.directions[1].bytes);
    const values = [`#${flow.id}`, ...flow.endpoints, packets.toString(), bytes.toString(), states[flow.state] ?? flow.state];
    row.append(...values.map((value, index) => el('td', value, index < 5 ? 'mono' : '')));
    row.addEventListener('click', () => this.select(flow.id));
    row.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        this.select(flow.id);
      }
    });
    return row;
  }

  async select(id) {
    if (!this.status || !id) return;
    const serial = ++this.selection;
    const path = sessionPath(this.status.id, `/flows/${id}`);
    try {
      const flow = await json(path);
      if (serial !== this.selection) return;
      this.selected = id;
      this.flow = flow;
      this.path = path;
      for (const row of this.rows.children) row.setAttribute('aria-selected', String(row.dataset.id === id));
      byId('flow-packets').hidden = false;
      byId('flow-prompt').hidden = true;
      byId('flow-details').hidden = false;
      const sides = flow.endpoints.map((endpoint, index) => {
        const side = index === 0 ? 'A' : 'B';
        return `${side} ${endpoint}（${flow.directions[index].packets} 包）`;
      });
      const time = flow.first_time ? ` · ${utc(flow.first_time)}–${utc(flow.last_time)} UTC` : '';
      const note = flow.missing_start ? ' · 起点未捕获' : '';
      byId('flow-caption').textContent = `#${id} · ${sides.join(' · ')}${time}${note}`;
      this.stream.reset();
      this.http.reset();
      this.show(this.view);
    } catch (error) {
      if (serial === this.selection) this.onError(error.message);
    }
  }

  show(view) {
    if (!this.flow) return;
    this.view = view;
    const stream = view === 'stream';
    byId('show-stream').setAttribute('aria-pressed', String(stream));
    byId('show-http').setAttribute('aria-pressed', String(!stream));
    byId('stream-view').hidden = !stream;
    byId('http-view').hidden = stream;
    if (stream && !this.stream.path) this.stream.setFlow(this.path, this.flow);
    if (!stream && !this.http.path) this.http.setFlow(this.path);
  }
}
