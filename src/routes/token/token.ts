import { RequestHandler } from 'express';
import { getNewOrUpdateCurrentSession, pgClient } from '@/utils';
import { sendError } from '@/errors';
import { Joi, refreshToken } from '@/validation';
import NodeCache from 'node-cache';

const invalidTokenCache = new NodeCache({ stdTTL: 60 });

const tokenCache = new NodeCache({ stdTTL: 100, checkperiod: 120 });

export const tokenSchema = Joi.object({
  refreshToken,
}).meta({ className: 'TokenSchema' });

export const tokenHandler: RequestHandler<{},
  {},
  { refreshToken: string }> = async (req, res) => {
  const { refreshToken } = req.body;

  if (invalidTokenCache.get(refreshToken) === true) {
    return sendError(res, 'invalid-refresh-token');
  }

  const user = await pgClient.getUserByRefreshToken(refreshToken);

  if (!user) {
    invalidTokenCache.set(refreshToken, true);
    return sendError(res, 'invalid-refresh-token');
  }

  const existingToken = tokenCache.get(user.id);

  if (existingToken) {
    return res.send(existingToken as any);
  }

  // 1 in 10 request will delete expired refresh tokens
  // TODO: CRONJOB in the future.
  if (Math.random() < 0.001) {
    // no await
    await pgClient.deleteExpiredRefreshTokens();
  }

  const session = await getNewOrUpdateCurrentSession({
    user,
    currentRefreshToken: refreshToken,
  });

  tokenCache.set(user.id, session);

  return res.send(session);
};
