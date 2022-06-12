import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Session } from 'src/auth/entity/session.entry';
import { DataSource } from 'typeorm';
import { JwtAccessPayload } from '../types';

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService, dataSource: DataSource) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('ACCESS_SECRET'),
      passReqToCallback: true,
    });
    this.sessionRepository = dataSource.getRepository(Session);
  }

  private sessionRepository;

  async validate(req: Request, payload: JwtAccessPayload) {
    const accessToken = req?.get('authorization')?.replace('Bearer', '').trim();

    const findAccessToekn = await this.sessionRepository.findOneBy({
      access_token: accessToken,
    });

    if (!findAccessToekn)
      throw new ForbiddenException('Access token не найден');

    return payload;
  }
}
