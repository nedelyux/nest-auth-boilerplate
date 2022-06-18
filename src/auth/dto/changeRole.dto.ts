import { IsNotEmpty, IsIn } from 'class-validator';
import { Role } from 'src/auth/enums';

export class ChangeRoleDto {
  @IsNotEmpty()
  userId: number;

  @IsNotEmpty()
  @IsIn(Object.values(Role))
  role: Role;
}
