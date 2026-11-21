import { json, query, sessionPath } from './api.js';
import { byId, el, endpoint, utc } from './dom.js';

const PAGE_SIZE = 256;
const ROW_HEIGHT = 34;
const HEADER_HEIGHT = 35;
const BUFFER = 6;

export class PacketList {
  constructor({ onSelect, onError }) {
    this.onSelect = onSelect;
    this.onError = onError;
    this.scroller = byId('packet-scroll');
    this.rows = byId('packet-rows');
    this.empty = byId('packet-empty');
    this.items = [];
    this.status = null;
    this.revision = 0;
    this.filter = '';
    this.follow = true;
    this.start = 0n;
    this.cursor = 0n;
    this.history = [];
    this.more = false;
    this.selected = null;
    this.scroller.addEventListener('wheel', event => {
      if (event.deltaY < 0 && this.follow) this.setFollow(false);
    }, { passive: true });
    this.scroller.addEventListener('scroll', () => {
      if (!this.frame) this.frame = requestAnimationFrame(() => {
        this.frame = null;
        this.render();
      });
    });
    this.rows.addEventListener('click', event => this.activate(event));
    this.rows.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        this.activate(event);
      }
    });
    byId('older').addEventListener('click', () => this.older());
    byId('newer').addEventListener('click', () => this.newer());
    byId('follow').addEventListener('change', event => {
      this.setFollow(event.target.checked);
      if (this.follow) this.refresh(0);
    });
  }

  setStatus(status) {
    const changed = this.status?.id !== status?.id;
    const progress = this.status?.seen !== status?.seen || this.status?.first !== status?.first;
    this.status = status;
    if (changed) {
      this.revision++;
      this.loading = false;
      this.history = [];
      this.items = [];
      this.selected = null;
      this.start = 0n;
      this.cursor = 0n;
      this.more = false;
      this.render();
      this.footer();
    }
    if (status && (changed || (progress && this.follow))) this.refresh(0);
  }

  setFollow(follow) {
    this.follow = follow;
    byId('follow').checked = follow;
  }

  setFilter(filter) {
    this.filter = filter;
    this.history = [];
    this.setFollow(!filter);
    return this.load(this.initial());
  }

  selectFlow(flow) {
    this.flow = flow;
    this.history = [];
    this.setFollow(flow == null && !this.filter);
    return this.load(this.initial());
  }

  initial() {
    const seen = BigInt(this.status?.seen ?? 0);
    return this.follow && seen > BigInt(PAGE_SIZE) ? seen - BigInt(PAGE_SIZE)
      : BigInt(this.status?.first ?? 1) - 1n;
  }

  refresh(delay = 125) {
    if (this.timer) return;
    this.timer = setTimeout(async () => {
      this.timer = null;
      if (this.loading) {
        this.refresh();
        return;
      }
      await this.load(this.initial(), { preserveScroll: true });
    }, delay);
  }

  async load(after, { preserveScroll = false } = {}) {
    const revision = ++this.revision;
    const status = this.status;
    if (!status) return;
    this.loading = true;
    const params = query({ after, until: status.seen, limit: PAGE_SIZE, filter: this.filter, flow: this.flow });
    try {
      const page = await json(sessionPath(status.id, `/packets?${params}`));
      if (revision !== this.revision) return;
      this.start = after;
      this.cursor = BigInt(page.cursor);
      this.more = page.more;
      this.items = page.packets;
      if (!preserveScroll) this.scroller.scrollTop = 0;
      this.render();
      if (this.follow) {
        this.scroller.scrollTop = this.scroller.scrollHeight;
        this.render();
      }
      this.footer(page.skipped);
    } catch (error) {
      if (revision === this.revision) this.onError(error.message);
    } finally {
      if (revision === this.revision) this.loading = false;
    }
  }

  older() {
    this.setFollow(false);
    const first = BigInt(this.status?.first ?? 1) - 1n;
    const previous = this.history.pop() ?? this.start - BigInt(PAGE_SIZE);
    this.load(previous > first ? previous : first);
  }

  newer() {
    if (!this.more) return;
    this.setFollow(false);
    this.history.push(this.start);
    this.load(this.cursor);
  }

  async jump(id) {
    this.setFollow(false);
    this.flow = null;
    this.filter = '';
    byId('display-filter').value = '';
    this.history = [];
    await this.load(BigInt(id) - 1n);
    await this.select(id);
  }

  activate(event) {
    const row = event.target.closest('tr[data-id]');
    if (row) this.select(row.dataset.id);
  }

  async select(id) {
    this.setFollow(false);
    this.selected = String(id);
    this.render();
    await this.onSelect(this.selected);
  }

  render() {
    this.empty.hidden = this.items.length > 0;
    byId('packet-empty-message').textContent = this.status
      ? '当前窗口或显示过滤器没有匹配记录。'
      : '开始实时捕获，或在启动时指定离线文件。';
    if (!this.items.length) {
      this.rows.replaceChildren();
      return;
    }
    const visible = Math.ceil(this.scroller.clientHeight / ROW_HEIGHT) + BUFFER * 2;
    const first = Math.max(0, Math.floor((this.scroller.scrollTop - HEADER_HEIGHT) / ROW_HEIGHT) - BUFFER);
    const last = Math.min(this.items.length, first + visible);
    const focused = this.rows.contains(document.activeElement)
      ? document.activeElement?.dataset.id : null;
    const fragment = document.createDocumentFragment();
    if (first > 0) fragment.append(this.spacer(first));
    for (const packet of this.items.slice(first, last)) fragment.append(this.row(packet));
    if (last < this.items.length) fragment.append(this.spacer(this.items.length - last));
    this.rows.replaceChildren(fragment);
    if (focused) this.rows.querySelector(`[data-id="${focused}"]`)?.focus({ preventScroll: true });
  }

  spacer(count) {
    const row = el('tr', '', 'spacer');
    row.setAttribute('aria-hidden', 'true');
    const cell = el('td');
    cell.colSpan = 7;
    cell.style.height = `${count * ROW_HEIGHT}px`;
    row.append(cell);
    return row;
  }

  row(packet) {
    const row = el('tr');
    row.dataset.id = packet.id;
    row.tabIndex = 0;
    row.setAttribute('aria-selected', String(packet.id === this.selected));
    const protocol = el('span', packet.protocol, 'protocol');
    protocol.dataset.protocol = packet.protocol;
    for (const [index, text] of [
      packet.id,
      utc(packet.timestamp),
      endpoint(packet.source, packet.source_port),
      endpoint(packet.destination, packet.destination_port),
      '',
      String(packet.original_len),
      packet.issue ?? (packet.fragmented ? 'IP 分片' : '—'),
    ].entries()) {
      const cell = el('td', text, index < 4 || index === 5 ? 'mono' : '');
      if (index === 4) cell.append(protocol);
      if (text) cell.title = text;
      row.append(cell);
    }
    return row;
  }

  footer(skipped = '0') {
    const first = BigInt(this.status?.first ?? 1) - 1n;
    byId('older').disabled = this.start <= first;
    byId('newer').disabled = !this.more;
    const note = skipped === '0' ? '' : ` · ${skipped} 条已淘汰`;
    byId('page-summary').textContent = `${this.items.length} 条记录${note}`;
  }
}
