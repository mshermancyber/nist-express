// Shared upload-limit configuration. Centralises the size caps and
// adds a per-request timeout middleware to defeat slowloris-style
// upload attacks.

import multer, { Multer } from 'multer';
import { NextFunction, Request, Response, RequestHandler } from 'express';

export const SIZE_IAC_BYTES   = 2  * 1024 * 1024;   // 2 MB
export const SIZE_SBOM_BYTES  = 8  * 1024 * 1024;   // 8 MB
export const SIZE_CLOUD_BYTES = 16 * 1024 * 1024;   // 16 MB

const UPLOAD_DEADLINE_MS = 30_000;

export function uploadLimits(maxBytes: number): Multer {
  return multer({ limits: { fileSize: maxBytes, files: 1, fields: 10 } });
}

// Multer raises a MulterError when the limit is exceeded. Without an
// explicit handler Express returns 500 with a stack trace. This
// wrapper turns the upload chain into a route-scoped handler that
// reports a clean 413 / 400 instead.
export function uploadHandler(upload: Multer): RequestHandler {
  const single = upload.single('file');
  return (req, res, next) => {
    single(req, res, err => {
      if (!err) return next();
      const code = (err as { code?: string } | undefined)?.code;
      if (code === 'LIMIT_FILE_SIZE') {
        res.status(413).json({ error: 'file exceeds upload size limit' });
        return;
      }
      if (code === 'LIMIT_UNEXPECTED_FILE') {
        res.status(400).json({ error: 'unexpected file field (use "file")' });
        return;
      }
      res.status(400).json({ error: 'upload failed', detail: (err as Error).message });
    });
  };
}

// Sets a deadline for the request lifecycle. If the body / multipart
// stream isn't done within UPLOAD_DEADLINE_MS, abort. Use ONLY on
// upload routes (it would punish slow legitimate clients otherwise).
export function uploadDeadline(req: Request, res: Response, next: NextFunction): void {
  const timer = setTimeout(() => {
    if (!res.headersSent) res.status(408).json({ error: 'upload too slow — request timed out' });
    req.socket.destroy();
  }, UPLOAD_DEADLINE_MS);
  res.on('finish', () => clearTimeout(timer));
  res.on('close', () => clearTimeout(timer));
  next();
}
