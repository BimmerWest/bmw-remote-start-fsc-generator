import { generateFsc } from './core.mjs';

const form = document.querySelector('#generator-form');
const button = document.querySelector('#generate');
const status = document.querySelector('#status');

let publicDataPromise;

function loadPublicData() {
  publicDataPromise ??= fetch('./mdg1_public_data.json').then((response) => {
    if (!response.ok) throw new Error(`Could not load public data (${response.status})`);
    return response.json();
  });
  return publicDataPromise;
}

function downloadFsc(bytes, filename) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  button.disabled = true;
  status.className = 'status';
  status.textContent = 'Building record…';
  try {
    const data = await loadPublicData();
    const vin = form.elements.vin7.value;
    const appId = parseInt(form.elements.appid.value, 16);
    const templateFile = form.elements.template.files[0];
    const template = templateFile ? new Uint8Array(await templateFile.arrayBuffer()) : null;
    const result = generateFsc(vin, appId, data, template);
    const filename = `${result.vin}_${result.appId.toString(16).toUpperCase().padStart(4, '0')}.fsc`;
    downloadFsc(result.bytes, filename);
    status.className = 'status success';
    status.textContent = `${filename} generated · ${result.bytes.length} bytes · signature self-check passed`;
  } catch (error) {
    status.className = 'status error';
    status.textContent = error instanceof Error ? error.message : 'Generation failed';
  } finally {
    button.disabled = false;
  }
});
