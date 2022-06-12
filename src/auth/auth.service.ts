import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import * as bcrypt from 'bcrypt';

import { LoginDto, RegisterDto } from './dto';
import { JwtAccessPayload, JwtRefreshPayload, Tokens } from './types';
import { Role } from 'src/auth/enums';
import { DataSource } from 'typeorm';
import { User } from 'src/auth/entity/user.entity';
import { Session } from 'src/auth/entity/session.entry';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private config: ConfigService,
    private dataSource: DataSource,
  ) {
    this.userRepository = this.dataSource.getRepository(User);
    this.sessionRepository = this.dataSource.getRepository(Session);
  }

  private userRepository;
  private sessionRepository;

  async register(dto: RegisterDto, response: Response): Promise<Tokens> {
    const findAlredyExistUser = await this.userRepository.findOneBy({
      email: dto.email,
    });

    // проверка пользователя на укникальность email
    if (findAlredyExistUser) {
      throw new BadRequestException(
        'Пользователь с таким email уже существует',
      );
    }

    // хэшируем пароль с перцем и солью
    const hash = await bcrypt.hash(
      dto.password + this.config.get<string>('PEPPER'),
      Number(this.config.get<string>('SALT_ROUNDS')),
    );

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    let tokens: Tokens;

    try {
      // создаем пользователя
      const user = new User();

      user.email = dto.email;
      user.password = hash;
      user.role = Role.User;

      const createdUser = await queryRunner.manager.save(user);

      // создаем токены
      tokens = await this.getTokens(user);

      // создаем сессию
      const session = new Session();
      session.access_token = tokens.accessToken;
      session.refresh_token = tokens.refreshToken;
      session.user = createdUser;

      await queryRunner.manager.save(session);

      await queryRunner.commitTransaction();
    } catch (err) {
      await queryRunner.rollbackTransaction();

      throw new BadRequestException('Не удалось зарегистрировать пользователя');
    } finally {
      await queryRunner.release();
    }

    // сохраняем токен в cookie
    response.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
    });

    return tokens;
  }

  async login(dto: LoginDto, response: Response): Promise<Tokens> {
    // ищем по email
    const findUser = await this.userRepository.findOneBy({
      email: dto.email,
    });

    if (!findUser) throw new ForbiddenException('Пользователь не найден');

    // сверяем пароли
    const isMatchPassword = await bcrypt.compare(
      dto.password + this.config.get<string>('PEPPER'),
      findUser.password,
    );
    if (!isMatchPassword) throw new ForbiddenException('Неверный пароль');

    // получаем токены
    const tokens = await this.getTokens(findUser);

    // создаем сессию
    const session = new Session();
    session.access_token = tokens.accessToken;
    session.refresh_token = tokens.refreshToken;
    session.user = findUser;

    await this.sessionRepository.save(session);

    // сохраняем токен в cookie
    response.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
    });

    return tokens;
  }

  async refreshTokens(id: number, rt: string, response): Promise<Tokens> {
    // ищем пользователя по id
    const findUser = await this.userRepository.findOneBy({
      id,
    });

    if (!findUser) throw new ForbiddenException('Пользователь не найден');

    // ищем существующую сессию
    const findSession = await this.sessionRepository.findOne({
      where: {
        user: {
          id: 1,
        },
        refresh_token: rt,
      },
    });

    if (!findSession) throw new ForbiddenException('Сессия не найдена');

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    // создаем токены
    const tokens = await this.getTokens(findUser);

    try {
      // создаем новую сессию
      const newSession = new Session();

      newSession.access_token = tokens.accessToken;
      newSession.refresh_token = tokens.refreshToken;
      newSession.user = findUser;

      // сохраняем новую сессию
      await queryRunner.manager.save(newSession);
      // удаляем старую сессию
      await queryRunner.manager.remove(findSession);

      await queryRunner.commitTransaction();
    } catch (err) {
      await queryRunner.rollbackTransaction();

      throw new BadRequestException('Не удалось обновиить сессию');
    } finally {
      await queryRunner.release();
    }

    // сохраняем токен в cookie
    response.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
    });

    return tokens;
  }

  async getTokens(user): Promise<Tokens> {
    const jwtAccessPayload: JwtAccessPayload = {
      sub: user.id,
      role: user.role,
    };
    const jwtRefreshPayload: JwtRefreshPayload = {
      sub: user.id,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtAccessPayload, {
        secret: this.config.get<string>('ACCESS_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtRefreshPayload, {
        secret: this.config.get<string>('REFRESH_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }
}
