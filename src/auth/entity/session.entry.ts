import { User } from 'src/auth/entity/user.entity';
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity()
export class Session {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, (user) => user.sessions)
  user: User;

  @Column({
    nullable: true,
  })
  accessToken: string;

  @Column()
  refreshToken: string;

  @Column({
    nullable: true,
  })
  browserName: string;

  @Column({
    nullable: true,
  })
  osName: string;

  @Column({
    type: 'timestamptz',
  })
  expiresInRefresh: Date;

  @CreateDateColumn({
    type: 'timestamptz',
  })
  createdDate: Date;

  @UpdateDateColumn({
    type: 'timestamptz',
  })
  updatedDate: Date;
}
