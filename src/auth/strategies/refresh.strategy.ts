import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtRefreshPayload, JwtPayloadWithRefresh } from '../types';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(config: ConfigService) {
    super({
      // получаем refresh токен либо из заголовка либо из cookie
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req) => {
          return req.cookies['refreshToken'] || null;
        },
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      secretOrKey: config.get<string>('REFRESH_SECRET'),
      passReqToCallback: true,
    });
  }

  validate(req: Request, payload: JwtRefreshPayload): JwtPayloadWithRefresh {
    const refreshToken =
      req?.get('authorization')?.replace('Bearer', '').trim() ||
      req.cookies['refreshToken'];

    // зачем-то проверяем еще раз
    if (!refreshToken) throw new ForbiddenException('Refresh token malformed');

    return {
      ...payload,
      refreshToken,
    };
  }
}
