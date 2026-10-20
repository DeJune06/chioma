import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { PermissionAction, PermissionResource } from './permission.entity';

/**
 * A permission an admin has granted to another admin.
 * Role defaults still apply; this row adds a permission the grantee did not have.
 */
@Entity('admin_permission_delegations')
@Index(['granteeId', 'resource', 'action'], { unique: true })
export class AdminPermissionDelegation {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'grantor_id', type: 'uuid' })
  grantorId: string;

  @Column({ name: 'grantee_id', type: 'uuid' })
  granteeId: string;

  @Column({ type: 'varchar', length: 50 })
  resource: PermissionResource;

  @Column({ type: 'varchar', length: 50 })
  action: PermissionAction;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
