ALTER TABLE one_time_token DROP CONSTRAINT IF EXISTS one_time_token_purpose_check;
ALTER TABLE one_time_token ADD CONSTRAINT one_time_token_purpose_check
  CHECK (purpose IN ('password_reset','email_verification','magic_auth'));
