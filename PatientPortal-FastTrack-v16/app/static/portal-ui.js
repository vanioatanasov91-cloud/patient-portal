/* Optional progressive enhancement for report upload. Nothing is uploaded until
   the staff submits the existing CSRF-protected form. No medical data stored. */
(() => {
  'use strict';
  for (const zone of document.querySelectorAll('[data-file-drop]')) {
    const input = document.getElementById(zone.dataset.fileDrop);
    if (!input) continue;
    const label = zone.querySelector('.chosen-file');
    const show = () => {
      const item = input.files && input.files[0];
      if (label) label.textContent = item ? `Избран файл: ${item.name}` : '';
    };
    zone.addEventListener('click', () => input.click());
    zone.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
    });
    for (const type of ['dragenter', 'dragover']) {
      zone.addEventListener(type, e => { e.preventDefault(); zone.classList.add('drag-over'); });
    }
    for (const type of ['dragleave', 'drop']) {
      zone.addEventListener(type, e => { e.preventDefault(); zone.classList.remove('drag-over'); });
    }
    zone.addEventListener('drop', e => {
      const files = e.dataTransfer && e.dataTransfer.files;
      if (!files || files.length !== 1) return;
      if (!files[0].name.toLowerCase().endsWith('.pdf')) { if (label) label.textContent = 'Приема се само PDF файл.'; return; }
      if (files[0].size > 15 * 1024 * 1024) { if (label) label.textContent = 'Файлът надвишава 15 MB.'; return; }
      try { input.files = files; show(); } catch (_e) { if (label) label.textContent = 'Изберете файла от полето по-горе.'; }
    });
    input.addEventListener('change', show);
  }
})();
// v1.5: confirmations only for destructive or credential-reset operations.
document.querySelectorAll('[data-confirm]').forEach(button => {
  button.addEventListener('click', event => {
    if (!window.confirm(button.getAttribute('data-confirm'))) event.preventDefault();
  });
});
document.querySelectorAll('form[data-confirm-form]').forEach(form => {
  form.addEventListener('submit', event => {
    if (!window.confirm(form.getAttribute('data-confirm-form'))) event.preventDefault();
  });
});
// Set a sensible exam date default, without overwriting the staff member's input.
const examDate = document.querySelector('#upload-section input[name="exam_date"]');
if (examDate && !examDate.value) examDate.value = new Date().toLocaleDateString('en-CA');
