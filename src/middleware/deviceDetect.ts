import type { Request, Response, NextFunction } from 'express';

export type DeviceClass = 'ios' | 'android' | 'desktop';

// Tablets are intentionally folded into 'desktop' — they have the
// real estate for the sidebar+main grid and match the existing
// 1024px CSS breakpoint behavior. iPad on iPadOS 13+ reports its UA
// as macOS, which naturally falls through to 'desktop' as well.
export function detectDevice(ua: string | undefined): DeviceClass {
  if (!ua) return 'desktop';
  if (/iPad/i.test(ua)) return 'desktop';
  if (/Android/i.test(ua) && !/Mobile/i.test(ua)) return 'desktop';
  if (/iPhone|iPod/i.test(ua)) return 'ios';
  if (/Android/i.test(ua)) return 'android';
  return 'desktop';
}

export function deviceDetect(req: Request, res: Response, next: NextFunction): void {
  const cls = detectDevice(req.headers['user-agent']);
  (req as Request & { deviceClass?: DeviceClass }).deviceClass = cls;
  res.setHeader('X-Device-Class', cls);
  next();
}
