import type { Request, Response, NextFunction, RequestHandler } from 'express';

/** Express 4 does not forward rejected async handlers automatically. */
export function asyncHandler(handler: (req: Request, res: Response, next: NextFunction) => Promise<void>): RequestHandler {
  return (req, res, next) => { void Promise.resolve().then(() => handler(req, res, next)).catch(next); };
}
