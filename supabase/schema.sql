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

-- ================= Media managed from the admin panel =================
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('ldrf-media','ldrf-media', true, 52428800, array['image/jpeg','image/png','image/webp','video/mp4','video/webm'])
on conflict (id) do update set public = true, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "ldrf media public read" on storage.objects;
create policy "ldrf media public read" on storage.objects for select to anon, authenticated using (bucket_id = 'ldrf-media');
drop policy if exists "ldrf media admin insert" on storage.objects;
create policy "ldrf media admin insert" on storage.objects for insert to authenticated with check (bucket_id = 'ldrf-media' and public.ldrf_is_admin());
drop policy if exists "ldrf media admin update" on storage.objects;
create policy "ldrf media admin update" on storage.objects for update to authenticated using (bucket_id = 'ldrf-media' and public.ldrf_is_admin());
drop policy if exists "ldrf media admin delete" on storage.objects;
create policy "ldrf media admin delete" on storage.objects for delete to authenticated using (bucket_id = 'ldrf-media' and public.ldrf_is_admin());

create table if not exists public.ldrf_gallery (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  kind text not null default 'photo' check (kind in ('photo','video')),
  url text not null,
  path text,              -- storage path when uploaded from admin; null for built-in site images
  poster text,            -- thumbnail for videos
  caption text check (caption is null or char_length(caption) <= 160),
  sort int not null default 0
);
create table if not exists public.ldrf_course_images (
  course text primary key,
  url text not null,
  path text,
  updated_at timestamptz not null default now()
);
alter table public.ldrf_gallery enable row level security;
alter table public.ldrf_course_images enable row level security;

drop policy if exists "public read gallery" on public.ldrf_gallery;
create policy "public read gallery" on public.ldrf_gallery for select to anon, authenticated using (true);
drop policy if exists "admins manage gallery" on public.ldrf_gallery;
create policy "admins manage gallery" on public.ldrf_gallery for all to authenticated using (public.ldrf_is_admin()) with check (public.ldrf_is_admin());
drop policy if exists "public read course images" on public.ldrf_course_images;
create policy "public read course images" on public.ldrf_course_images for select to anon, authenticated using (true);
drop policy if exists "admins manage course images" on public.ldrf_course_images;
create policy "admins manage course images" on public.ldrf_course_images for all to authenticated using (public.ldrf_is_admin()) with check (public.ldrf_is_admin());
grant select on public.ldrf_gallery, public.ldrf_course_images to anon;
grant select, insert, update, delete on public.ldrf_gallery, public.ldrf_course_images to authenticated;

-- Seed the gallery once with the photos/videos already on the website
insert into public.ldrf_gallery (kind, url, poster, caption, sort)
select * from (values
  ('photo','/assets/img/calli-class-1.jpg',null,'Calligraphy class in progress',10),
  ('photo','/assets/img/computer-lab.jpg',null,'RGLM computer lab',20),
  ('photo','/assets/img/tailoring-class.jpg',null,'Cutting & tailoring class',30),
  ('photo','/assets/img/calli-class-2.jpg',null,'Calligraphy & painting practice',40),
  ('photo','/assets/img/tally-lab.jpg',null,'Tally & accounting lab',50),
  ('photo','/assets/img/calli-poster.jpg',null,'Urdu calligraphy course – admissions open',60),
  ('photo','/assets/img/tailoring-poster.jpg',null,'Cutting & Tailoring course',70),
  ('photo','/assets/img/urdu-calli.jpg',null,'Urdu Calligraphy – Session 2026',80),
  ('photo','/assets/img/calli-courses.jpg',null,'Calligraphy course levels',90),
  ('photo','/assets/img/computer-banner.jpg',null,'Computer courses – basic to advanced',100),
  ('photo','/assets/img/tally-poster.jpg',null,'Learn Tally with GST',110),
  ('video','/assets/video/highlights.mp4','/assets/video/highlights.jpg','LDRF × RGLM Highlights',10),
  ('video','/assets/video/computer-tally.mp4','/assets/video/computer-tally.jpg','Computer & Tally Lab',20),
  ('video','/assets/video/calligraphy-tailoring.mp4','/assets/video/calligraphy-tailoring.jpg','Calligraphy & Tailoring',30)
) v(kind,url,poster,caption,sort)
where not exists (select 1 from public.ldrf_gallery);

-- ================= Courses / programmes managed from the admin panel =================
create table if not exists public.ldrf_courses (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  name text not null unique check (char_length(name) between 2 and 80),
  image_url text,
  image_path text,                 -- storage path when uploaded from admin
  badge text check (badge is null or char_length(badge) <= 30),          -- e.g. ADMISSIONS OPEN
  highlight text check (highlight is null or char_length(highlight) <= 40), -- e.g. 3 Levels
  includes text check (includes is null or char_length(includes) <= 400),
  tag text check (tag is null or char_length(tag) <= 40),                -- e.g. Job Oriented
  subtitle text check (subtitle is null or char_length(subtitle) <= 60),
  footer text check (footer is null or char_length(footer) <= 60),       -- e.g. Certificate Provided
  sort int not null default 0,
  active boolean not null default true
);
alter table public.ldrf_courses enable row level security;
drop policy if exists "public read active courses" on public.ldrf_courses;
create policy "public read active courses" on public.ldrf_courses for select to anon, authenticated using (active or public.ldrf_is_admin());
drop policy if exists "admins manage courses" on public.ldrf_courses;
create policy "admins manage courses" on public.ldrf_courses for all to authenticated using (public.ldrf_is_admin()) with check (public.ldrf_is_admin());
grant select on public.ldrf_courses to anon;
grant select, insert, update, delete on public.ldrf_courses to authenticated;

-- Seed once with the courses already on the website (keeping any custom photos set earlier)
insert into public.ldrf_courses (name, image_url, image_path, badge, highlight, includes, tag, subtitle, footer, sort)
select v.name, coalesce(ci.url, v.img), ci.path, v.badge, v.highlight, v.includes, v.tag, v.subtitle, v.footer, v.sort
from (values
  ('Calligraphy & Graphic Design','/assets/img/calli-class-2.jpg','ADMISSIONS OPEN','3 Levels','Basic (letter forms, handwriting), Foundation (typography, composition, digital & traditional graphics) and Advanced (scripts, flourishing, graphic design integration, portfolio)','Creative Career','Urdu Calligraphy • Session 2026','Certificate Provided',10),
  ('Mehndi Designing',null,'NEW BATCH','Course','Mehndi design patterns and application techniques for self-employment','Self-Employment','For Women','Certificate Provided',20),
  ('Cutting & Tailoring','/assets/img/tailoring-class.jpg','FOR WOMEN','5 Modules','Cutting & Stitching, Dress Designing, Pattern Making, Fabric Knowledge & Measurement, Hand & Machine Stitching','Self-Reliance','Modern Machines & Equipment','Certificate Provided',30),
  ('Computer Training','/assets/img/computer-lab.jpg','BASIC TO ADVANCED','Basic to Advanced','Computer Basics, Graphic Designing, Coding & Programming and computer applications for the modern workplace','Job Oriented','Practical Lab Training','Certificate Provided',40),
  ('Tally Financial Accounting','/assets/img/tally-lab.jpg','100% JOB ORIENTED','Tally with GST','Accounting, Banking, Billing, Manufacturing, Inventory, TDS & TCS, Taxation (GST) and Payroll','Certified Professional','Complete Accounting & Taxation','Certificate Provided',50)
) v(name,img,badge,highlight,includes,tag,subtitle,footer,sort)
left join public.ldrf_course_images ci on ci.course = v.name
where not exists (select 1 from public.ldrf_courses);
