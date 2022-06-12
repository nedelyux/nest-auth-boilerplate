import { Controller, Get } from '@nestjs/common';
import { Role } from 'src/auth/enums';
import { Roles } from 'src/common/decorators';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Roles(Role.Admin)
  @Get('admin')
  profile(): string {
    return this.appService.getHelloAdmin();
  }
}
