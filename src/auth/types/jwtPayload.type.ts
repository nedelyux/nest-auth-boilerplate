import { Role } from 'src/auth/enums';

export type JwtAccessPayload = {
  sub: number;
  role: Role;
};

export type JwtRefreshPayload = {
  sub: number;
};
