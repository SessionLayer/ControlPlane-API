-- V1 baseline migration — SessionLayer Control Plane.
--
-- Intentionally a no-op. Its only job is to prove Flyway runs end-to-end at
-- startup (creating flyway_schema_history and recording version 1). The real
-- schema (config-vs-runtime entities, Design section 12A / FR-DATA-1) lands in
-- Session Two. Do NOT add application tables here.
SELECT 1;
