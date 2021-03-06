import { Session } from 'src/auth/entity/session.entry';
import { Role } from 'src/auth/enums';
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  email: string;

  @Column()
  password: string;

  @Column({ default: Role.User })
  role: Role;

  @OneToMany(() => Session, (session) => session.user)
  sessions: Session[];

  @CreateDateColumn({
    type: 'timestamptz',
  })
  createdDate: Date;

  @UpdateDateColumn({
    type: 'timestamptz',
  })
  updatedDate: Date;
}
