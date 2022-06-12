import { JwtRefreshPayload } from '.';

export type JwtPayloadWithRefresh = JwtRefreshPayload & {
  refreshToken: string;
};
