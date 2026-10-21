import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from '../users/entities/user.entity';
import { DelegatePermissionDto } from './dto/delegate-permission.dto';
import { AdminPermissionDelegation } from './entities/admin-permission-delegation.entity';
import {
  PermissionAction,
  PermissionResource,
} from './entities/permission.entity';
import { RbacService } from './rbac.service';

const ADMIN_ROLES = new Set<string>([UserRole.ADMIN, UserRole.SUPER_ADMIN]);

@Injectable()
export class PermissionDelegationService {
  constructor(
    @InjectRepository(AdminPermissionDelegation)
    private readonly delegations: Repository<AdminPermissionDelegation>,
    @InjectRepository(User)
    private readonly users: Repository<User>,
    private readonly rbacService: RbacService,
  ) {}

  async delegate(
    grantor: { id: string; role: string },
    dto: DelegatePermissionDto,
  ): Promise<AdminPermissionDelegation> {
    this.assertAdmin(grantor.role, 'Only admins can delegate permissions');

    if (grantor.id === dto.granteeId) {
      throw new BadRequestException(
        'Admins cannot delegate permissions to themselves',
      );
    }

    if (
      !this.rbacService.hasPermission(grantor.role, dto.resource, dto.action)
    ) {
      throw new ForbiddenException(
        'Cannot delegate a permission you do not hold',
      );
    }

    const grantee = await this.users.findOne({ where: { id: dto.granteeId } });
    if (!grantee) {
      throw new NotFoundException('Admin not found');
    }
    this.assertAdmin(
      grantee.role,
      'Permissions can only be delegated to other admins',
    );

    const existing = await this.delegations.findOne({
      where: {
        granteeId: dto.granteeId,
        resource: dto.resource,
        action: dto.action,
      },
    });
    if (existing) {
      return existing;
    }

    return this.delegations.save(
      this.delegations.create({
        grantorId: grantor.id,
        granteeId: dto.granteeId,
        resource: dto.resource,
        action: dto.action,
      }),
    );
  }

  async granteeHas(
    granteeId: string,
    resource: PermissionResource,
    action: PermissionAction,
  ): Promise<boolean> {
    const direct = await this.delegations.findOne({
      where: { granteeId, resource, action },
    });
    if (direct) {
      return true;
    }
    if (action === PermissionAction.MANAGE) {
      return false;
    }
    const manage = await this.delegations.findOne({
      where: { granteeId, resource, action: PermissionAction.MANAGE },
    });
    return !!manage;
  }

  private assertAdmin(role: string, message: string): void {
    if (!ADMIN_ROLES.has(role)) {
      throw new ForbiddenException(message);
    }
  }
}
