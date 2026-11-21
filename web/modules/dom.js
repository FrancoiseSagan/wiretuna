export const byId = id => document.getElementById(id);

export function el(tag, text = '', className = '') {
  const node = document.createElement(tag);
  if (text !== '') node.textContent = text;
  if (className) node.className = className;
  return node;
}

export function endpoint(address, port) {
  if (!address) return '—';
  if (port == null) return address;
  return address.includes(':') ? `[${address}]:${port}` : `${address}:${port}`;
}

export function utc(time) {
  if (!time) return '—';
  const date = new Date(time.seconds * 1000);
  if (!Number.isFinite(date.getTime())) return '—';
  return `${date.toISOString().slice(11, 19)}.${String(time.nanoseconds).padStart(9, '0').slice(0, 6)}`;
}
