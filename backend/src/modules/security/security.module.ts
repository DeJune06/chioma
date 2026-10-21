import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SecurityController } from './security.controller';
import { SecurityEventsService } from './security-events.service';
import { ThreatDetectionService } from './threat-detection.service';
import { SecurityIncidentService } from './security-incident.service';
import { ComplianceService } from './compliance.service';
import { RbacService } from './rbac.service';
import { EncryptionService } from './encryption.service';
import { BlockchainAuditService } from './blockchain-audit.service';
import { PermissionsGuard } from './guards/permissions.guard';
import { SecurityEvent } from './entities/security-event.entity';
import { ThreatEvent } from './entities/threat-event.entity';
import { Role } from './entities/role.entity';
import { Permission } from './entities/permission.entity';
import { AdminPermissionDelegation } from './entities/admin-permission-delegation.entity';
import { PermissionDelegationService } from './permission-delegation.service';
import { User } from '../users/entities/user.entity';
import { AuditLog } from '../audit/entities/audit-log.entity';
import { DatabaseEncryptionKeyService } from './database-encryption-key.service';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [
    ConfigModule,
    AuditModule,
    TypeOrmModule.forFeature([
      SecurityEvent,
      ThreatEvent,
      Role,
      Permission,
      AdminPermissionDelegation,
      User,
      AuditLog,
    ]),
  ],
  controllers: [SecurityController],
  providers: [
    SecurityEventsService,
    ThreatDetectionService,
    SecurityIncidentService,
    ComplianceService,
    RbacService,
    PermissionDelegationService,
    EncryptionService,
    BlockchainAuditService,
    DatabaseEncryptionKeyService,
    PermissionsGuard,
  ],
  exports: [
    SecurityEventsService,
    ThreatDetectionService,
    SecurityIncidentService,
    ComplianceService,
    RbacService,
    PermissionDelegationService,
    EncryptionService,
    BlockchainAuditService,
    DatabaseEncryptionKeyService,
    PermissionsGuard,
  ],
})
export class SecurityModule {}
