import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { APP_GUARD } from '@nestjs/core';
import { AccessGuard } from './common/guards';
import { ConfigModule } from '@nestjs/config';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/auth/entity/user.entity';
import { Session } from 'src/auth/entity/session.entry';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost',
      port: 5432,
      username: 'test',
      password: 'test',
      database: 'test',
      synchronize: true,
      logging: true,
      entities: [User, Session],
      subscribers: [],
      migrations: [],
    }),
    ConfigModule.forRoot({ isGlobal: true }),
    AuthModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    // закрываем все не @Public() роуты для access токена
    {
      provide: APP_GUARD,
      useClass: AccessGuard,
    },
    // Возможность проверки на роли
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
  ],
})
export class AppModule {}
