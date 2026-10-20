import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Stores permissions one admin has granted to another admin.
 */
export class CreateAdminPermissionDelegations1930700000000 implements MigrationInterface {
  name = 'CreateAdminPermissionDelegations1930700000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "admin_permission_delegations" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "grantor_id" uuid NOT NULL,
        "grantee_id" uuid NOT NULL,
        "resource" character varying(50) NOT NULL,
        "action" character varying(50) NOT NULL,
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_admin_permission_delegations" PRIMARY KEY ("id"),
        CONSTRAINT "FK_admin_permission_delegations_grantor" FOREIGN KEY ("grantor_id") REFERENCES "users"("id") ON DELETE CASCADE,
        CONSTRAINT "FK_admin_permission_delegations_grantee" FOREIGN KEY ("grantee_id") REFERENCES "users"("id") ON DELETE CASCADE,
        CONSTRAINT "UQ_admin_permission_delegations_grantee_perm" UNIQUE ("grantee_id", "resource", "action")
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP TABLE IF EXISTS "admin_permission_delegations"`,
    );
  }
}
