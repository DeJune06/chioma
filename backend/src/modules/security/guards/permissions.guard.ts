import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RbacService } from '../rbac.service';
import { PermissionDelegationService } from '../permission-delegation.service';
import {
  PermissionAction,
  PermissionResource,
} from '../entities/permission.entity';
import { UserRole } from '../../users/entities/user.entity';

export const PERMISSIONS_KEY = 'required_permissions';

export interface RequiredPermission {
  resource: PermissionResource;
  action: PermissionAction;
}

export const RequirePermission = (
  resource: PermissionResource,
  action: PermissionAction,
) => Reflect.metadata(PERMISSIONS_KEY, [{ resource, action }]);

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private rbacService: RbacService,
    private delegationService: PermissionDelegationService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const required = this.reflector.getAllAndOverride<RequiredPermission[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!required || required.length === 0) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest<{
      user?: { id?: string; role?: UserRole };
    }>();

    if (!user?.role) {
      throw new ForbiddenException('User not authenticated');
    }

    for (const { resource, action } of required) {
      if (this.rbacService.hasPermission(user.role, resource, action)) {
        continue;
      }

      const delegated =
        !!user.id &&
        (user.role === UserRole.ADMIN || user.role === UserRole.SUPER_ADMIN) &&
        (await this.delegationService.granteeHas(user.id, resource, action));

      if (!delegated) {
        throw new ForbiddenException('Insufficient permissions');
      }
    }

    return true;
  }
}
