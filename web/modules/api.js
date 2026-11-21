const ROOT = '/api/v1';

export async function request(path, options = {}) {
  const response = await fetch(ROOT + path, options);
  if (!response.ok) {
    const detail = await response.json().catch(() => null);
    throw new Error(detail?.message ?? `请求失败（${response.status}）`);
  }
  return response;
}

export async function json(path, options) {
  return (await request(path, options)).json();
}

export function post(path, body) {
  return json(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
}

export function sessionPath(id, suffix = '') {
  return `/sessions/${id}${suffix}`;
}

export function query(parameters) {
  const search = new URLSearchParams();
  for (const [name, value] of Object.entries(parameters)) {
    if (value != null && value !== '') search.set(name, String(value));
  }
  return search.toString();
}
