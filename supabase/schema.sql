-- LDRF × RGLM landing page: form submissions + admin access
create table if not exists public.ldrf_admins (
  email text primary key,
  created_at timestamptz not null default now()
);

create table if not exists public.ldrf_enrollments (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  name text not null check (char_length(name) between 2 and 120),
  mobile text not null check (mobile ~ '^[6-9][0-9]{9}$'),
  program text not null check (char_length(program) between 2 and 120),
  location text not null check (char_length(location) between 2 and 120),
  status text not null default 'new' check (status in ('new','contacted','enrolled','closed')),
  notes text
);

create table if not exists public.ldrf_contacts (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  name text not null check (char_length(name) between 2 and 120),
  mobile text not null check (mobile ~ '^[6-9][0-9]{9}$'),
  email text check (email is null or char_length(email) <= 160),
  subject text check (subject is null or char_length(subject) <= 80),
  message text not null check (char_length(message) between 2 and 2000),
  status text not null default 'new' check (status in ('new','replied','closed')),
  notes text
);

create or replace function public.ldrf_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.ldrf_admins where lower(email) = lower(auth.jwt() ->> 'email'));
$$;

alter table public.ldrf_admins enable row level security;
alter table public.ldrf_enrollments enable row level security;
alter table public.ldrf_contacts enable row level security;

drop policy if exists "public can submit enrollment" on public.ldrf_enrollments;
create policy "public can submit enrollment" on public.ldrf_enrollments
  for insert to anon, authenticated with check (status = 'new' and notes is null);
drop policy if exists "admins read enrollments" on public.ldrf_enrollments;
create policy "admins read enrollments" on public.ldrf_enrollments for select to authenticated using (public.ldrf_is_admin());
drop policy if exists "admins update enrollments" on public.ldrf_enrollments;
create policy "admins update enrollments" on public.ldrf_enrollments for update to authenticated using (public.ldrf_is_admin()) with check (public.ldrf_is_admin());
drop policy if exists "admins delete enrollments" on public.ldrf_enrollments;
create policy "admins delete enrollments" on public.ldrf_enrollments for delete to authenticated using (public.ldrf_is_admin());

drop policy if exists "public can submit contact" on public.ldrf_contacts;
create policy "public can submit contact" on public.ldrf_contacts
  for insert to anon, authenticated with check (status = 'new' and notes is null);
drop policy if exists "admins read contacts" on public.ldrf_contacts;
create policy "admins read contacts" on public.ldrf_contacts for select to authenticated using (public.ldrf_is_admin());
drop policy if exists "admins update contacts" on public.ldrf_contacts;
create policy "admins update contacts" on public.ldrf_contacts for update to authenticated using (public.ldrf_is_admin()) with check (public.ldrf_is_admin());
drop policy if exists "admins delete contacts" on public.ldrf_contacts;
create policy "admins delete contacts" on public.ldrf_contacts for delete to authenticated using (public.ldrf_is_admin());

drop policy if exists "admins see own admin row" on public.ldrf_admins;
create policy "admins see own admin row" on public.ldrf_admins for select to authenticated using (lower(email) = lower(auth.jwt() ->> 'email'));

grant insert on public.ldrf_enrollments, public.ldrf_contacts to anon;
grant select, insert, update, delete on public.ldrf_enrollments, public.ldrf_contacts to authenticated;
grant select on public.ldrf_admins to authenticated;
revoke select, update, delete on public.ldrf_enrollments, public.ldrf_contacts from anon;

-- Only emails listed in ldrf_admins may create an account in this project
create or replace function public.ldrf_only_admin_signup() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.ldrf_admins where lower(email) = lower(new.email)) then
    raise exception 'Signups are restricted to LDRF admins';
  end if;
  return new;
end $$;
drop trigger if exists ldrf_only_admin_signup on auth.users;
create trigger ldrf_only_admin_signup before insert on auth.users
  for each row execute function public.ldrf_only_admin_signup();
