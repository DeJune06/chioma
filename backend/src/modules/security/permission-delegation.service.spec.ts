import {
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User, UserRole } from '../users/entities/user.entity';
import { AdminPermissionDelegation } from './entities/admin-permission-delegation.entity';
import {
  PermissionAction,
  PermissionResource,
} from './entities/permission.entity';
import { PermissionDelegationService } from './permission-delegation.service';
import { RbacService } from './rbac.service';

describe('PermissionDelegationService', () => {
  const delegations = {
    findOne: jest.fn(),
    create: jest.fn((value) => value),
    save: jest.fn(async (value) => ({ id: 'delegation-1', ...value })),
  };
  const users = { findOne: jest.fn() };
  const rbacService = { hasPermission: jest.fn() };

  let service: PermissionDelegationService;

  const grantor = { id: 'admin-1', role: UserRole.ADMIN };
  const dto = {
    granteeId: 'admin-2',
    resource: PermissionResource.AUDIT,
    action: PermissionAction.READ,
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    const moduleRef = await Test.createTestingModule({
      providers: [
        PermissionDelegationService,
        {
          provide: getRepositoryToken(AdminPermissionDelegation),
          useValue: delegations,
        },
        { provide: getRepositoryToken(User), useValue: users },
        { provide: RbacService, useValue: rbacService },
      ],
    }).compile();
    service = moduleRef.get(PermissionDelegationService);
  });

  it('grants a held permission to another admin', async () => {
    rbacService.hasPermission.mockReturnValue(true);
    users.findOne.mockResolvedValue({ id: 'admin-2', role: UserRole.ADMIN });
    delegations.findOne.mockResolvedValue(null);

    const saved = await service.delegate(grantor, dto);

    expect(saved).toMatchObject({
      grantorId: 'admin-1',
      granteeId: 'admin-2',
      resource: PermissionResource.AUDIT,
      action: PermissionAction.READ,
    });
  });

  it('returns the existing grant instead of duplicating it', async () => {
    rbacService.hasPermission.mockReturnValue(true);
    users.findOne.mockResolvedValue({ id: 'admin-2', role: UserRole.ADMIN });
    delegations.findOne.mockResolvedValue({ id: 'existing' });

    await expect(service.delegate(grantor, dto)).resolves.toEqual({
      id: 'existing',
    });
    expect(delegations.save).not.toHaveBeenCalled();
  });

  it('rejects a grant the admin does not hold', async () => {
    rbacService.hasPermission.mockReturnValue(false);
    await expect(service.delegate(grantor, dto)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('rejects grants to non-admins and to the grantor', async () => {
    rbacService.hasPermission.mockReturnValue(true);
    users.findOne.mockResolvedValue({ id: 'user-1', role: UserRole.USER });
    await expect(service.delegate(grantor, dto)).rejects.toBeInstanceOf(
      ForbiddenException,
    );

    await expect(
      service.delegate(grantor, { ...dto, granteeId: grantor.id }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects an unknown grantee', async () => {
    rbacService.hasPermission.mockReturnValue(true);
    users.findOne.mockResolvedValue(null);
    await expect(service.delegate(grantor, dto)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it('treats a delegated manage permission as the specific action', async () => {
    delegations.findOne
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ id: 'manage' });

    await expect(
      service.granteeHas(
        'admin-2',
        PermissionResource.PAYMENTS,
        PermissionAction.READ,
      ),
    ).resolves.toBe(true);
  });
});
