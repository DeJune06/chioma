import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsUUID } from 'class-validator';
import {
  PermissionAction,
  PermissionResource,
} from '../entities/permission.entity';

export class DelegatePermissionDto {
  @ApiProperty({ format: 'uuid' })
  @IsUUID()
  granteeId: string;

  @ApiProperty({ enum: PermissionResource })
  @IsEnum(PermissionResource)
  resource: PermissionResource;

  @ApiProperty({ enum: PermissionAction })
  @IsEnum(PermissionAction)
  action: PermissionAction;
}
