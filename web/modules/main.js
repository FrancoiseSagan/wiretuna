import { json, post, request, sessionPath } from './api.js';
import { PacketDetails } from './details.js';
import { byId, el } from './dom.js';
import { PacketList } from './packets.js';

const phaseNames = {
  idle: '空闲', starting: '正在启动', running: '运行中',
  stopping: '正在停止', finished: '已完成', failed: '失败',
};
const captureForm = byId('capture-form');
const interfaceSelect = byId('interface');
let status = null;
let live = false;
let mutating = false;

function notice(message = '') {
  const element = byId('notice');
  element.textContent = message;
  element.hidden = !message;
}

const details = new PacketDetails(notice);
const packets = new PacketList({
  onSelect: id => status ? details.select(status.id, id) : undefined,
  onError: notice,
});

function renderStatus() {
  const phase = status?.phase ?? 'idle';
  const finished = ['finished', 'failed'].includes(phase);
  byId('phase').textContent = phaseNames[phase] ?? phase;
  byId('phase').dataset.phase = phase;
  byId('session-label').textContent = status?.label ?? '等待会话';
  byId('seen').textContent = status?.seen ?? '0';
  byId('retained').textContent = String(status?.retained ?? 0);
  byId('dropped').textContent = status?.input_dropped ?? '0';
  byId('evicted').textContent = status?.evicted ?? '0';
  byId('backend-dropped').textContent = String(status?.backend?.dropped ?? '—');
  interfaceSelect.disabled = !live || Boolean(status) || mutating;
  byId('capture-filter').disabled = !live || Boolean(status) || mutating;
  byId('snaplen').disabled = !live || Boolean(status) || mutating;
  byId('start').disabled = !live || Boolean(status) || mutating || !interfaceSelect.value;
  byId('stop').disabled = !status || finished || phase === 'stopping' || mutating;
  byId('clear').disabled = !finished || mutating;
}

function setStatus(next) {
  if (status?.id !== next?.id) details.clear();
  if (next?.error && next.error !== status?.error) notice(next.error);
  status = next;
  packets.setStatus(next);
  renderStatus();
}

async function mutate(action) {
  if (mutating) return;
  mutating = true;
  notice();
  renderStatus();
  try {
    await action();
  } catch (error) {
    notice(error.message);
  } finally {
    mutating = false;
    renderStatus();
  }
}

captureForm.addEventListener('submit', event => {
  event.preventDefault();
  mutate(async () => setStatus(await post('/sessions', {
    interface: interfaceSelect.value,
    filter: byId('capture-filter').value,
    snaplen: Number(byId('snaplen').value),
  })));
});
interfaceSelect.addEventListener('change', renderStatus);
byId('stop').addEventListener('click', () => mutate(async () => {
  if (status) setStatus(await post(sessionPath(status.id, '/stop')));
}));
byId('clear').addEventListener('click', () => mutate(async () => {
  if (!status) return;
  await request(sessionPath(status.id), { method: 'DELETE' });
  setStatus(null);
}));
byId('display-form').addEventListener('submit', event => {
  event.preventDefault();
  notice();
  packets.setFilter(byId('display-filter').value.trim());
});
byId('reset-filter').addEventListener('click', () => {
  byId('display-filter').value = '';
  notice();
  packets.setFilter('');
});

renderStatus();
json('/interfaces').then(value => {
  live = value.live;
  interfaceSelect.append(el('option', '选择接口'));
  interfaceSelect.firstElementChild.value = '';
  for (const { name, description } of value.interfaces) {
    const option = el('option', description ? `${name} · ${description}` : name);
    option.value = name;
    interfaceSelect.append(option);
  }
  byId('capture-note').textContent = live ? '' : '当前构建用于查看离线文件。';
  renderStatus();
}).catch(error => notice(error.message));

const events = new EventSource('/api/v1/events');
events.addEventListener('status', event => setStatus(JSON.parse(event.data).session));
events.addEventListener('open', () => connection(true));
events.addEventListener('error', () => connection(false));

function connection(online) {
  byId('connection').textContent = online ? '本机服务已连接' : '正在重新连接';
  byId('connection-indicator').classList.toggle('online', online);
}
