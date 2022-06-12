import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtAccessPayload } from 'src/auth/types';

export const GetCurrentUserId = createParamDecorator(
  (_: undefined, context: ExecutionContext): number => {
    const request = context.switchToHttp().getRequest();
    const user = request.user as JwtAccessPayload;
    return user.sub;
  },
);
