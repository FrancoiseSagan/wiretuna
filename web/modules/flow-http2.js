import { json } from './api.js';
import { byId, el } from './dom.js';

const sides = ['A → B', 'B → A'];
const issues = {
  frame_limit: '已达到帧显示上限',
  incomplete_frame_header: '帧头不完整',
  invalid_preface: '连接前言缺少起始 SETTINGS 帧',
  incomplete_frame_payload: '帧数据不完整',
  incomplete_field_block: '报头块缺少后续 CONTINUATION 帧',
  interrupted_field_block: '报头块被其他帧打断',
  invalid_frame: '帧结构无效',
  hpack_unavailable: '缺少后续解码所需的 HPACK 状态',
  unexpected_continuation: '未观察到报头块起始帧',
  hpack_limit: '报头压缩数据超出解析上限',
  hpack_invalid: 'HPACK 压缩数据无效',
  stream_gap: '解析止于首个 TCP 字节缺口',
  settings_limit: '已达到设置字段显示上限',
};
const fieldNames = {
  frame_type: '类型编号',
  dependency: '依赖流',
  weight: '权重',
  data_bytes: '数据字节',
  error_code: '错误码',
  setting_id: '未知设置编号',
  setting_value: '设置值',
  last_stream: '最后处理的流',
  window_increment: '窗口增量',
};

function formatFlags(frame) {
  const hex = `0x${frame.flags.toString(16).padStart(2, '0')}`;
  const has = mask => (frame.flags & mask) !== 0;
  const signals = [
    ['DATA', 'HEADERS'].includes(frame.kind) && has(0x01) && 'END_STREAM',
    ['HEADERS', 'PUSH_PROMISE', 'CONTINUATION'].includes(frame.kind) && has(0x04) && 'END_HEADERS',
    ['SETTINGS', 'PING'].includes(frame.kind) && has(0x01) && 'ACK',
  ].filter(Boolean);
  return [hex, ...signals].join(' · ');
}

export class Http2View {
  constructor({ onError, onPacket }) {
    this.onError = onError;
    this.onPacket = onPacket;
    this.frames = byId('http2-frames');
    this.detail = byId('http2-frame-detail');
    this.note = byId('http2-note');
    this.content = byId('http2-content');
    this.select = byId('http2-stream');
    this.exchange = byId('http2-exchange');
    this.serial = 0;
    this.select.addEventListener('change', () => this.showStream());
  }

  reset() {
    this.path = null;
    this.serial++;
  }

  async setFlow(path) {
    this.path = path;
    const serial = ++this.serial;
    this.content.hidden = true;
    this.note.textContent = '正在读取 HTTP/2 帧…';
    try {
      const report = await json(`${path}/http2`);
      if (serial === this.serial) this.render(report);
    } catch (error) {
      if (serial !== this.serial) return;
      this.note.textContent = '读取 HTTP/2 帧失败。';
      this.onError(error.message);
    }
  }

  render(report) {
    if (!report.recognized) {
      this.note.textContent = '当前连接中未识别到明文 HTTP/2 前言。';
      return;
    }
    const notes = [report.upgraded && '经 HTTP/1.1 升级', report.missing_start && '连接起点未捕获'];
    report.directions.forEach((direction, index) => {
      const warnings = [
        issues[direction.issue],
        direction.overlap_conflict && 'TCP 重叠字节有冲突',
        direction.limited && '部分字节超出保留上限',
      ].filter(Boolean);
      if (warnings.length) notes.push(`${sides[index]} ${warnings.join('，')}`);
    });
    if (!report.streams.length) notes.push('尚未观察到完整的帧头。');
    this.note.textContent = notes.filter(Boolean).join(' · ');
    if (!report.streams.length) return;
    this.streams = new Map(report.streams.map(stream => [String(stream.id), stream.frames]));
    this.select.replaceChildren(...report.streams.map(stream => {
      const option = el('option', stream.id === 0 ? '0 · 连接控制' : String(stream.id));
      option.value = stream.id;
      return option;
    }));
    this.select.value = report.streams.find(stream => stream.id !== 0)?.id ?? 0;
    this.content.hidden = false;
    this.showStream();
  }

  showStream() {
    const frames = this.streams.get(this.select.value);
    const selected = Number(this.select.value);
    const request = frames.find(frame => frame.head?.method && (frame.promised_stream ?? frame.stream_id) === selected);
    const statuses = frames.filter(frame => frame.head?.status).map(frame => frame.head.status);
    const summary = [
      request && [request.head.method, request.head.path ?? request.head.authority].filter(Boolean).join(' '),
      statuses.length && `响应 ${statuses.join('、')}`,
    ].filter(Boolean);
    this.exchange.textContent = summary.join(' · ');
    const list = el('div', '', 'http-transaction');
    for (const frame of frames) {
      const hint = frame.head?.status ?? frame.head?.method;
      const label = [sides[frame.direction], frame.kind, hint ?? `${frame.length} B`].join(' · ');
      const button = el('button', label);
      button.type = 'button';
      button.setAttribute('aria-pressed', 'false');
      button.addEventListener('click', () => {
        list.querySelector('[aria-pressed="true"]')?.setAttribute('aria-pressed', 'false');
        button.setAttribute('aria-pressed', 'true');
        this.showFrame(frame);
      });
      list.append(button);
    }
    this.frames.replaceChildren(list);
    list.firstElementChild.click();
  }

  showFrame(frame) {
    const source = el('button', `来源包 #${frame.packet}`, 'plain');
    source.type = 'button';
    source.addEventListener('click', () => this.onPacket(frame.packet));
    const fields = el('dl');
    const values = [
      ['方向', sides[frame.direction]],
      ['流编号', frame.stream_id],
      ['字节偏移', frame.offset],
      ['帧负载字节', frame.kind === 'HTTP/1.1 Upgrade' ? null : frame.length],
      ['标志', frame.kind === 'HTTP/1.1 Upgrade' ? null : formatFlags(frame)],
      ['推送流编号', frame.promised_stream],
      ...frame.fields.map(field => [fieldNames[field.key] ?? field.key, field.value]),
      ...Object.entries(frame.head ?? {}).map(([key, value]) => [`:${key}`, value]),
    ];
    for (const [key, value] of values) {
      if (value == null) continue;
      const row = el('div');
      row.append(el('dt', key), el('dd', String(value)));
      fields.append(row);
    }
    this.detail.replaceChildren(el('strong', frame.kind), source, fields);
    if (frame.issue) this.detail.append(el('p', issues[frame.issue] ?? frame.issue, 'sub-note'));
  }
}
