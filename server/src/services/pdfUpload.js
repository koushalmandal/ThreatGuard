function badRequest(message) {
  throw Object.assign(new Error(message), { status: 400 });
}

function validatePdfUpload(file) {
  if (!file) badRequest('Choose a PDF file.');
  if (!Buffer.isBuffer(file.buffer) || file.size === 0 || file.buffer.length === 0) badRequest('Choose a non-empty PDF file.');
  if (!/\.pdf$/i.test(file.originalname || '') || file.mimetype !== 'application/pdf' || file.buffer.subarray(0, 5).toString() !== '%PDF-') {
    badRequest('File must have a .pdf extension, PDF MIME type, and valid PDF signature.');
  }
  return true;
}

module.exports = validatePdfUpload;
