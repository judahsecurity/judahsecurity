-- Judah Security ASM - Database Initialization Script
-- This script runs automatically when the PostgreSQL container starts for the first time

-- Enable UUID extension (useful for future enhancements)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant necessary permissions to the application user
GRANT ALL PRIVILEGES ON DATABASE asm_db TO asm_user;

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'Judah Security ASM database initialized successfully!';
END $$;

-- ============================================================================
-- MIGRATIONS: Applied after tables are created by SQLAlchemy
-- These use IF NOT EXISTS / IF EXISTS to be idempotent
-- ============================================================================

-- Port verification fields (for nmap deep inspection after masscan)
-- This function will be called after tables exist
CREATE OR REPLACE FUNCTION apply_port_verification_migration()
RETURNS void AS $$
BEGIN
    -- Check if port_services table exists before adding columns
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'port_services') THEN
        -- Add verification columns if they don't exist
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name = 'port_services' AND column_name = 'verified') THEN
            ALTER TABLE port_services ADD COLUMN verified BOOLEAN DEFAULT FALSE;
            RAISE NOTICE 'Added verified column to port_services';
        END IF;
        
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name = 'port_services' AND column_name = 'verified_at') THEN
            ALTER TABLE port_services ADD COLUMN verified_at TIMESTAMP;
            RAISE NOTICE 'Added verified_at column to port_services';
        END IF;
        
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name = 'port_services' AND column_name = 'verified_state') THEN
            ALTER TABLE port_services ADD COLUMN verified_state VARCHAR(50);
            RAISE NOTICE 'Added verified_state column to port_services';
        END IF;
        
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name = 'port_services' AND column_name = 'verification_scanner') THEN
            ALTER TABLE port_services ADD COLUMN verification_scanner VARCHAR(50);
            RAISE NOTICE 'Added verification_scanner column to port_services';
        END IF;
        
        -- Create indexes if they don't exist
        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_port_services_verified') THEN
            CREATE INDEX idx_port_services_verified ON port_services (verified);
        END IF;
        
        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_port_services_verified_state') THEN
            CREATE INDEX idx_port_services_verified_state ON port_services (verified_state);
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql;

















