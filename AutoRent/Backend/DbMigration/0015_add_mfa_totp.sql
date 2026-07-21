ALTER TABLE "users" ADD COLUMN "mfa_enabled" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "mfa_secret" varchar(255);--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "mfa_temp_secret" varchar(255);--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "mfa_backup_codes" varchar(2000);