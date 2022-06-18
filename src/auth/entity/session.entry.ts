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
  access_token: string;

  @Column()
  refresh_token: string;

  @Column({
    nullable: true,
  })
  browser_name: string;

  @Column({
    nullable: true,
  })
  os_name: string;

  @CreateDateColumn()
  createdDate: Date;

  @UpdateDateColumn()
  updatedDate: Date;
}
