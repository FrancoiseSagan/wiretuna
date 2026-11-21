import { json } from './api.js';
import { byId, el } from './dom.js';

const kinds = {
  dns_query: 'DNS 查询',
  dns_response: 'DNS 响应',
  client_hello: 'TLS ClientHello',
  server_hello: 'TLS ServerHello',
};
const issues = {
  dns_incomplete: 'DNS 帧不完整',
  dns_invalid_length: 'DNS 帧的长度小于报文头',
  tls_incomplete_record: 'TLS 记录不完整',
  tls_invalid_record: 'TLS 记录头无效',
  tls_incomplete_handshake: 'TLS 握手消息不完整',
  tls_invalid_hello: 'TLS Hello 消息格式无效',
  stream_gap: '解析止于首个 TCP 字节缺口',
  message_limit: '已达到消息显示上限',
};
const names = {
  'tls.sni': '服务器名称（SNI）',
  'tls.alpn': '应用协议（ALPN）',
  'tls.legacy_version': '兼容版本字段',
  'tls.offered_versions': '提议的版本',
  'tls.selected_version': '选定的版本',
  'tls.cipher_suites': '提议的密码套件',
  'tls.cipher_suite': '选定的密码套件',
  'tls.hello_retry_request': 'HelloRetryRequest',
};

export class ProtocolView {
  constructor({ onError, onPacket }) {
    this.onError = onError;
    this.onPacket = onPacket;
    this.note = byId('protocol-note');
    this.messages = byId('protocol-messages');
    this.detail = byId('stream-protocol-detail');
    this.serial = 0;
  }

  reset() {
    this.path = null;
    this.serial++;
  }

  async setFlow(path) {
    this.path = path;
    const serial = ++this.serial;
    this.note.textContent = '正在读取协议消息…';
    this.messages.replaceChildren();
    this.detail.replaceChildren();
    try {
      const report = await json(`${path}/protocols`);
      if (serial === this.serial) this.render(report);
    } catch (error) {
      if (serial !== this.serial) return;
      this.note.textContent = '读取协议消息失败。';
      this.onError(error.message);
    }
  }

  render(report) {
    if (!report.protocol) {
      this.note.textContent = '当前流中未识别到 TCP DNS 或 TLS 握手。';
      return;
    }
    const notes = [];
    if (report.protocol === 'tls') notes.push('仅显示捕获中可见的 TLS Hello 字段');
    if (report.missing_start) notes.push('连接起点未捕获');
    this.note.textContent = notes.join(' · ');
    const buttons = [];
    report.directions.forEach((direction, index) => {
      const side = index === 0 ? 'A → B' : 'B → A';
      const rows = direction.messages.map(message => this.button(message, side));
      buttons.push(...rows);
      const warnings = [
        issues[direction.issue],
        direction.overlap_conflict && 'TCP 重叠字节有冲突',
        direction.limited && '部分字节超出保留上限',
      ].filter(Boolean);
      if (rows.length || warnings.length) {
        this.messages.append(el('div', '', 'http-transaction'));
        this.messages.lastChild.append(el('span', side, 'muted'), ...rows);
        if (warnings.length) this.messages.lastChild.append(el('span', warnings.join(' · '), 'sub-note'));
      }
    });
    if (!buttons.length) this.messages.append(el('p', '没有可显示的完整消息。', 'empty'));
    else buttons[0].click();
  }

  button(message, side) {
    const hint = message.fields.find(field => ['dns.qry.name', 'tls.sni', 'tls.selected_version'].includes(field.key))?.value;
    const label = kinds[message.kind];
    const button = el('button', hint ? `${label} · ${hint}` : label);
    button.type = 'button';
    button.setAttribute('aria-pressed', 'false');
    button.addEventListener('click', () => {
      this.messages.querySelector('[aria-pressed="true"]')?.setAttribute('aria-pressed', 'false');
      button.setAttribute('aria-pressed', 'true');
      this.select(message, side);
    });
    return button;
  }

  select(message, side) {
    const source = el('button', `来源包 #${message.packet}`, 'plain');
    source.type = 'button';
    source.addEventListener('click', () => this.onPacket(message.packet));
    const fields = el('dl');
    for (const field of message.fields) {
      const row = el('div');
      row.append(el('dt', names[field.key] ?? field.key), el('dd', field.value));
      fields.append(row);
    }
    const caption = el('p', `${side} · 字节偏移 ${message.offset}`, 'muted');
    this.detail.replaceChildren(el('strong', kinds[message.kind]), source, caption, fields);
    if (message.issue) this.detail.append(el('p', issues[message.issue] ?? message.issue, 'sub-note'));
  }
}
