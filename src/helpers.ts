import { APPLICATION, JWT, REGISTRATION } from '@config/index'
import { NextFunction, Response, Request } from 'express'
import * as gravatar from 'gravatar'
import QRCode from 'qrcode'
import bcrypt from 'bcryptjs'
import { pwnedPassword } from 'hibp'
import { v4 as uuidv4 } from 'uuid'
import { gqlSdk } from './utils/gqlSDK'
import { UserFieldsFragment } from './utils/__generated__/graphql-request'
import { SessionUser } from './types'

/**
 * Create QR code.
 * @param secret Required OTP secret.
 */
export function createQR(secret: string): Promise<string> {
  return QRCode.toDataURL(secret)
}

/**
 * This wrapper function sends any route errors to `next()`.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function asyncWrapper(fn: any) {
  return function (req: Request, res: Response, next: NextFunction): void {
    fn(req, res, next).catch(next)
  }
}

export const getUserByEmail = async (email: string) => {
  const { users } = await gqlSdk.users({
    where: {
      email: {
        _eq: email
      }
    }
  })

  // if (users.length !== 1) {
  //   throw new Error('User does not exist.')
  // }

  return users[0]
}

export const getUserByTicket = async (ticket: string) => {
  const now = new Date()

  const { users } = await gqlSdk.users({
    where: {
      _and: [
        {
          ticket: {
            _eq: ticket
          }
        },
        {
          ticketExpiresAt: {
            _gt: now
          }
        }
      ]
    }
  })

  if (users.length !== 1) {
    return null
  }

  return users[0]
}

// TODO await request returns undefined if no user found!
export const getUser = async (userId: string | undefined) => {
  if (!userId) {
    throw new Error('User does not exists')
  }

  const { user } = await gqlSdk.user({
    id: userId
  })

  if (!user) {
    throw new Error('User does not exists')
  }

  return user
}

/**
 * Password hashing function.
 * @param password Password to hash.
 */
export const hashPassword = async (password: string): Promise<string> => {
  return await bcrypt.hash(password, 10)
}

/**
 * Checks password against the HIBP API.
 * @param password Password to check.
 */
export const isCompromisedPassword = async (password: string): Promise<boolean> => {
  return !!(REGISTRATION.HIBP_ENABLED && (await pwnedPassword(password)))
}

export const rotateTicket = async (oldTicket: string): Promise<string> => {
  const newTicket = uuidv4()

  await gqlSdk.rotateUsersTicket({
    oldTicket,
    newTicket,
    newTicketExpiresAt: new Date()
  })

  return newTicket
}

export function newRefreshExpiry(): number {
  const now = new Date()
  // 1 day = 1440 minutes
  const days = JWT.REFRESH_EXPIRES_IN / 1440

  return now.setDate(now.getDate() + days)
}

export const setRefreshToken = async (userId: string, refreshToken = uuidv4()) => {
  await gqlSdk.insertRefreshToken({
    refreshToken: {
      userId,
      refreshToken,
      expiresAt: new Date(newRefreshExpiry())
    }
  })

  return refreshToken
}

export const userWithEmailExists = async (email: string) => {
  return !!await getUserByEmail(email)
}

export const userIsAnonymous = async (userId: string) => {
  const { user } = await gqlSdk.user({
    id: userId
  })

  return user?.isAnonymous
}

export const getGravatarUrl = (email?: string) => {
  if (APPLICATION.GRAVATAR_ENABLED && email) {
    return gravatar.url(email, {
      r: APPLICATION.RATING,
      protocol: 'https',
      default: APPLICATION.GRAVATAR_DEFAULT
    })
  }
}

export const deanonymizeUser = async (user: UserFieldsFragment) => {
  // Gravatar is enabled and anonymous user has not added
  // an avatar yet
  const useGravatar = APPLICATION.GRAVATAR_ENABLED && !user.avatarUrl

  // update user
  user.avatarUrl = !useGravatar ? user.avatarUrl : getGravatarUrl(user.email)
  user.defaultRole = REGISTRATION.DEFAULT_USER_ROLE

  user.active = true

  const userRoles = REGISTRATION.DEFAULT_ALLOWED_USER_ROLES.map((role) => ({
    userId: user.id,
    createdAt: new Date(),
    role
  }))

  await gqlSdk.deanonymizeUser({
    userId: user.id,
    user,
    userRoles
  })
}

export const isWhitelistedEmail = async (email: string) => {
  const { AuthWhitelist } = await gqlSdk.isWhitelistedEmail({
    email
  })

  return !!AuthWhitelist
}

export function userToSessionUser(user: UserFieldsFragment): SessionUser {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl
  }
}
