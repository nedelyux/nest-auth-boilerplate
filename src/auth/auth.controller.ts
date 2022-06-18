import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ChangeRoleDto } from 'src/auth/dto/changeRole.dto';
import { Role } from 'src/auth/enums';

import {
  Public,
  GetCurrentUserId,
  GetCurrentUser,
  Roles,
} from '../common/decorators';
import { RefreshGuard } from '../common/guards';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  register(
    @Body() dto: RegisterDto,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<Tokens> {
    return this.authService.register(dto, request, response);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(
    @Body() dto: LoginDto,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<Tokens> {
    return this.authService.login(dto, request, response);
  }

  @Public()
  @UseGuards(RefreshGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUserId() userId: number,
    @Req() request: Request,
    @GetCurrentUser('refreshToken') refreshToken: string,
    @Res({ passthrough: true }) response: Response,
  ): Promise<Tokens> {
    return this.authService.refreshTokens(
      userId,
      refreshToken,
      request,
      response,
    );
  }

  @Post('change-role')
  @Roles(Role.Admin)
  @HttpCode(HttpStatus.OK)
  changeRole(@Body() dto: ChangeRoleDto) {
    return this.authService.changeRole(dto);
  }
}
