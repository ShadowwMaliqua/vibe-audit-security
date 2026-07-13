-- Intentionally vulnerable fixture: RLS is never enabled on these tables.
create table public.profiles (
  id uuid primary key,
  email text,
  is_admin boolean default false
);

create table public.orders (
  id serial primary key,
  user_id uuid references public.profiles(id),
  total numeric
);
