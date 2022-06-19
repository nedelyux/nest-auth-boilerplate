import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import * as bcrypt from 'bcrypt';
import * as parser from 'ua-parser-js';
import * as ms from 'ms';

import { LoginDto, RegisterDto } from './dto';
import { JwtAccessPayload, JwtRefreshPayload, Tokens } from './types';
import { Role } from 'src/auth/enums';
import { DataSource } from 'typeorm';
import { User } from 'src/auth/entity/user.entity';
import { Session } from 'src/auth/entity/session.entry';
import { ChangeRoleDto } from 'src/auth/dto/changeRole.dto';

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

  async register(
    dto: RegisterDto,
    request: Request,
    response: Response,
  ): Promise<Tokens> {
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
      session.accessToken = tokens.accessToken;
      session.refreshToken = tokens.refreshToken;
      session.user = createdUser;
      session.expiresInRefresh = new Date(
        Date.now() + ms(this.config.get<string>('REFRESH_EXPIRES_IN')),
      );

      const UAData = parser(request.headers['user-agent']);

      // сохраняем данные об агенете
      if (UAData.browser?.name) session.browserName = UAData.browser.name;
      if (UAData.os?.name) session.osName = UAData.os.name;

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

  async login(
    dto: LoginDto,
    request: Request,
    response: Response,
  ): Promise<Tokens> {
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
    session.accessToken = tokens.accessToken;
    session.refreshToken = tokens.refreshToken;
    session.user = findUser;

    session.expiresInRefresh = new Date(
      Date.now() + ms(this.config.get<string>('REFRESH_EXPIRES_IN')),
    );

    const UAData = parser(request.headers['user-agent']);

    // сохраняем данные об агенете
    if (UAData.browser?.name) session.browserName = UAData.browser.name;
    if (UAData.os?.name) session.osName = UAData.os.name;

    await this.sessionRepository.save(session);

    // сохраняем токен в cookie
    response.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
    });

    return tokens;
  }

  async refreshTokens(
    id: number,
    refreshToken: string,
    request: Request,
    response: Response,
  ): Promise<Tokens> {
    // ищем пользователя по id
    const findUser = await this.userRepository.findOneBy({
      id,
    });

    if (!findUser) throw new ForbiddenException('Пользователь не найден');

    // ищем существующую сессию
    const findSession: Session = await this.sessionRepository.findOne({
      where: {
        user: {
          id,
        },
        refreshToken,
      },
    });

    if (!findSession) throw new ForbiddenException('Сессия не найдена');

    // создаем токены
    const tokens = await this.getTokens(findUser);

    findSession.accessToken = tokens.accessToken;
    findSession.refreshToken = tokens.refreshToken;

    const UAData = parser(request.headers['user-agent']);

    // сохраняем данные об агенете
    if (UAData.browser?.name) findSession.browserName = UAData.browser.name;
    if (UAData.os?.name) findSession.osName = UAData.os.name;

    findSession.expiresInRefresh = new Date(
      Date.now() + ms(this.config.get<string>('REFRESH_EXPIRES_IN')),
    );

    // обновляем сессию
    await this.sessionRepository.save(findSession);

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
        expiresIn: this.config.get<string>('ACCESS_EXPIRES_IN'),
      }),
      this.jwtService.signAsync(jwtRefreshPayload, {
        secret: this.config.get<string>('REFRESH_SECRET'),
        expiresIn: this.config.get<string>('REFRESH_EXPIRES_IN'),
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async changeRole(dto: ChangeRoleDto) {
    const { userId, role } = dto;

    // ищем пользователя по id
    const findUser: User = await this.userRepository.findOneBy({
      id: userId,
    });

    if (!findUser) throw new ForbiddenException('Пользователь не найден');

    if (findUser.role === role)
      throw new ForbiddenException('Роль у пользователя уже установлена');

    const queryRunner = this.dataSource.createQueryRunner();
    try {
      await queryRunner.connect();
      await queryRunner.startTransaction();

      const user: User = await queryRunner.manager.findOneBy(User, {
        id: userId,
      });

      // Меняем роль
      user.role = role;

      let session = await queryRunner.manager.find(Session, {
        where: {
          user: {
            id: userId,
          },
        },
      });

      // удаляем все accessToken
      session = session.map((session) => ({
        ...session,
        accessToken: null,
      }));

      await queryRunner.manager.save(Session, session);
      await queryRunner.manager.save(User, user);

      await queryRunner.commitTransaction();
    } catch (err) {
      await queryRunner.rollbackTransaction();

      throw new BadRequestException('Не удалось установить роль');
    } finally {
      await queryRunner.release();
    }
  }
}
