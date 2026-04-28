-- Prototype schema (simple + demo-friendly)

create extension if not exists "uuid-ossp";

create table if not exists targets (
  id uuid primary key default uuid_generate_v4(),
  name text not null,
  address text not null, -- ip or hostname
  tags text[] not null default '{}',
  owner text,
  created_at timestamptz not null default now()
);

create type scan_run_status as enum ('queued', 'running', 'succeeded', 'failed');
create type scan_step_status as enum ('queued', 'running', 'succeeded', 'failed');
create type finding_status as enum ('open', 'triaged', 'in_progress', 'fixed', 'verified', 'false_positive', 'accepted_risk');
create type finding_severity as enum ('info', 'low', 'medium', 'high', 'critical');

create table if not exists scan_runs (
  id uuid primary key default uuid_generate_v4(),
  target_id uuid not null references targets(id) on delete cascade,
  profile text not null default 'network_surface_safe',
  status scan_run_status not null default 'queued',
  cancel_requested boolean not null default false,
  requested_by text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists scan_steps (
  id uuid primary key default uuid_generate_v4(),
  scan_run_id uuid not null references scan_runs(id) on delete cascade,
  name text not null,
  status scan_step_status not null default 'queued',
  started_at timestamptz,
  finished_at timestamptz,
  log text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists services (
  id uuid primary key default uuid_generate_v4(),
  target_id uuid not null references targets(id) on delete cascade,
  port int not null,
  protocol text not null default 'tcp',
  service_name text,
  product text,
  version text,
  banner text,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  unique (target_id, port, protocol)
);

create table if not exists findings (
  id uuid primary key default uuid_generate_v4(),
  target_id uuid not null references targets(id) on delete cascade,
  service_id uuid references services(id) on delete set null,
  title text not null,
  severity finding_severity not null,
  status finding_status not null default 'open',
  fingerprint text not null,
  evidence_redacted text not null default '',
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  last_scan_run_id uuid references scan_runs(id) on delete set null,
  unique (fingerprint)
);

create table if not exists finding_events (
  id uuid primary key default uuid_generate_v4(),
  finding_id uuid not null references findings(id) on delete cascade,
  type text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create type job_status as enum ('queued', 'running', 'succeeded', 'failed');

create table if not exists jobs (
  id uuid primary key default uuid_generate_v4(),
  type text not null, -- 'scan'
  status job_status not null default 'queued',
  payload jsonb not null,
  error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists pipeline_configs (
  id int primary key,
  config jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists audit_events (
  id uuid primary key default uuid_generate_v4(),
  actor text not null default 'system',
  action text not null,
  target text,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_jobs_status on jobs(status);
create index if not exists idx_scan_runs_target on scan_runs(target_id);
create index if not exists idx_findings_target on findings(target_id);
create index if not exists idx_audit_events_created_at on audit_events(created_at desc);

