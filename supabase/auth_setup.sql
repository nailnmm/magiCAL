-- =========================================================
-- SUPABASE AUTH SETUP (PROFILES + LOGIN-ONLY SECURITY)
-- =========================================================
-- This file is the single source of truth for authentication
-- logic (email, Apple, Google).
-- Safe to re-run (idempotent).
-- =========================================================


-- =========================================================
-- 01) PROFILES TABLE + RLS
-- =========================================================

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique,
  created_at timestamptz default now(),
  apple_sub text,
  google_sub text
);

alter table public.profiles enable row level security;

do $$
begin
  -- SELECT policy
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename  = 'profiles'
      and policyname = 'Profiles are viewable by owner'
  ) then
    create policy "Profiles are viewable by owner"
      on public.profiles
      for select
      using (auth.uid() = id);
  end if;

  -- INSERT policy
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename  = 'profiles'
      and policyname = 'Profiles are insertable by owner'
  ) then
    create policy "Profiles are insertable by owner"
      on public.profiles
      for insert
      with check (auth.uid() = id);
  end if;
end $$;


-- =========================================================
-- 02) UNIQUE PROVIDER IDENTIFIERS
-- =========================================================

create unique index if not exists profiles_apple_sub_key
  on public.profiles (apple_sub)
  where apple_sub is not null;

create unique index if not exists profiles_google_sub_key
  on public.profiles (google_sub)
  where google_sub is not null;


-- =========================================================
-- 03) AUTO-CREATE PROFILE ON AUTH USER CREATION
-- =========================================================

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
as $$
begin
  insert into public.profiles (id, email)
  values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
after insert on auth.users
for each row
execute procedure public.handle_new_user();


-- =========================================================
-- 04) RPC — APPLE LOGIN (LOGIN ONLY)
-- =========================================================

create or replace function public.can_login_with_apple(p_apple_sub text)
returns boolean
language sql
security definer
as $$
  select exists (
    select 1
    from public.profiles
    where apple_sub = p_apple_sub
  );
$$;

revoke all on function public.can_login_with_apple(text) from public;
grant execute on function public.can_login_with_apple(text)
  to anon, authenticated;


-- =========================================================
-- 05) RPC — GOOGLE LOGIN (LOGIN ONLY)
-- =========================================================

create or replace function public.can_login_with_google(p_google_sub text)
returns boolean
language sql
security definer
as $$
  select exists (
    select 1
    from public.profiles
    where google_sub = p_google_sub
  );
$$;

revoke all on function public.can_login_with_google(text) from public;
grant execute on function public.can_login_with_google(text)
  to anon, authenticated;


-- =========================================================
-- END OF FILE
-- =========================================================
