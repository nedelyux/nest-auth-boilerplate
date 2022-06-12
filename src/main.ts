import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // убираем все поля, которые не описанны в dto
      transform: true, // включаем автоматическое преобразование типов
    }),
  );
  await app.listen(3000);
}
bootstrap();
