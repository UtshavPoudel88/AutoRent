CREATE TYPE "public"."activity_log_status" AS ENUM('success', 'failure');--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "activity_logs" (
	"id" varchar(255) PRIMARY KEY NOT NULL,
	"user_id" varchar(255),
	"action" varchar(100) NOT NULL,
	"status" "activity_log_status" DEFAULT 'success' NOT NULL,
	"target_id" varchar(255),
	"ip_address" varchar(45),
	"user_agent" varchar(500),
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "activity_logs" ADD CONSTRAINT "activity_logs_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE SET NULL ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "activity_logs_user_id_idx" ON "activity_logs" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "activity_logs_action_idx" ON "activity_logs" USING btree ("action");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "activity_logs_created_at_idx" ON "activity_logs" USING btree ("created_at");