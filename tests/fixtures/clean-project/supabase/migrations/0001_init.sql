create table public.profiles (
  id uuid primary key,
  email text
);

alter table public.profiles enable row level security;

create policy "Users can read their own profile"
  on public.profiles for select
  using (auth.uid() = id);
