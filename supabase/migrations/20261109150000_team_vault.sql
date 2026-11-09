-- Bóveda del equipo. El servidor solo guarda texto cifrado: las contraseñas se cifran en la
-- extensión con la clave del equipo (PBKDF2 → AES-GCM) y Supabase nunca la ve.

-- ---------- Miembros e invitaciones ----------
create table public.team_members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  role text not null default 'member' check (role in ('admin', 'member')),
  created_at timestamptz not null default now()
);

create table public.team_invites (
  email text primary key check (email = lower(email)),
  role text not null default 'member' check (role in ('admin', 'member')),
  created_at timestamptz not null default now()
);

create or replace function public.is_team_member() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.team_members where user_id = auth.uid());
$$;

create or replace function public.is_team_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.team_members where user_id = auth.uid() and role = 'admin');
$$;

create or replace function public.my_role() returns text
language sql stable security definer set search_path = '' as $$
  select role from public.team_members where user_id = auth.uid();
$$;

-- Al crearse un usuario en Auth con un email invitado, entra al equipo.
create or replace function public.handle_new_auth_user() returns trigger
language plpgsql security definer set search_path = '' as $$
declare v_role text;
begin
  delete from public.team_invites where email = lower(new.email) returning role into v_role;
  if v_role is not null then
    insert into public.team_members (user_id, email, role) values (new.id, lower(new.email), v_role)
    on conflict (user_id) do nothing;
  end if;
  return new;
end;
$$;

create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_auth_user();

-- Admin: invitar (si el usuario ya existe en Auth, entra directo).
create or replace function public.invite_member(p_email text, p_role text default 'member') returns text
language plpgsql security definer set search_path = '' as $$
declare v_email text := lower(trim(p_email)); v_uid uuid;
begin
  if not public.is_team_admin() then raise exception 'not_admin'; end if;
  if p_role not in ('admin', 'member') then raise exception 'bad_role'; end if;
  if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then raise exception 'bad_email'; end if;
  select id into v_uid from auth.users where lower(email) = v_email;
  if v_uid is not null then
    insert into public.team_members (user_id, email, role) values (v_uid, v_email, p_role)
    on conflict (user_id) do update set role = excluded.role;
    return 'added';
  end if;
  insert into public.team_invites (email, role) values (v_email, p_role)
  on conflict (email) do update set role = excluded.role;
  return 'invited';
end;
$$;

create or replace function public.remove_member(p_user uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_team_admin() then raise exception 'not_admin'; end if;
  if (select role from public.team_members where user_id = p_user) = 'admin'
     and (select count(*) from public.team_members where role = 'admin') <= 1 then
    raise exception 'last_admin';
  end if;
  delete from public.team_members where user_id = p_user;
end;
$$;

create or replace function public.cancel_invite(p_email text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_team_admin() then raise exception 'not_admin'; end if;
  delete from public.team_invites where email = lower(trim(p_email));
end;
$$;

-- ---------- Bóveda ----------
-- Parámetros de la clave del equipo + un verificador cifrado para comprobar la contraseña.
create table public.vault_meta (
  id smallint primary key default 1 check (id = 1),
  salt text not null,
  iterations int not null check (iterations >= 100000),
  check_iv text not null,
  check_data text not null,
  key_version int not null default 1,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);

create table public.vault_items (
  id uuid primary key default gen_random_uuid(),
  iv text not null,
  data text not null, -- JSON del elemento, cifrado con AES-GCM
  key_version int not null,
  version int not null default 1,
  created_at timestamptz not null default now(),
  created_by uuid default auth.uid(),
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);

-- Auditoría y control de versiones; rechaza escrituras con una clave vieja.
create or replace function public.vault_items_stamp() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.key_version is distinct from (select key_version from public.vault_meta where id = 1) then
    raise exception 'stale_key';
  end if;
  new.updated_at := now();
  new.updated_by := auth.uid();
  if tg_op = 'INSERT' then
    new.version := 1;
    new.created_at := now();
    new.created_by := auth.uid();
  else
    new.id := old.id;
    new.created_at := old.created_at;
    new.created_by := old.created_by;
    new.version := old.version + 1;
  end if;
  return new;
end;
$$;

create trigger vault_items_stamp before insert or update on public.vault_items
  for each row execute function public.vault_items_stamp();

-- Admin: cambiar la clave del equipo re-cifrando TODOS los elementos en una sola transacción.
create or replace function public.rotate_team_key(
  p_salt text, p_iterations int, p_check_iv text, p_check_data text,
  p_expected_key_version int, p_items jsonb
) returns int
language plpgsql security definer set search_path = '' as $$
declare v_kv int; v_n int;
begin
  if not public.is_team_admin() then raise exception 'not_admin'; end if;
  select key_version into v_kv from public.vault_meta where id = 1 for update;
  if v_kv is distinct from p_expected_key_version then raise exception 'key_changed'; end if;
  perform 1 from public.vault_items for update;
  select count(*) into v_n from public.vault_items i
    where exists (select 1 from jsonb_array_elements(p_items) e where (e->>'id')::uuid = i.id);
  if v_n <> (select count(*) from public.vault_items) or v_n <> jsonb_array_length(p_items) then
    raise exception 'items_changed';
  end if;
  update public.vault_meta set salt = p_salt, iterations = p_iterations, check_iv = p_check_iv,
    check_data = p_check_data, key_version = v_kv + 1, updated_at = now(), updated_by = auth.uid()
    where id = 1;
  update public.vault_items i set iv = e->>'iv', data = e->>'data', key_version = v_kv + 1
    from jsonb_array_elements(p_items) e where (e->>'id')::uuid = i.id;
  return v_kv + 1;
end;
$$;

-- ---------- RLS y permisos ----------
alter table public.team_members enable row level security;
alter table public.team_invites enable row level security;
alter table public.vault_meta enable row level security;
alter table public.vault_items enable row level security;

create policy members_read on public.team_members for select to authenticated using (public.is_team_member());
create policy invites_read on public.team_invites for select to authenticated using (public.is_team_admin());
create policy meta_read on public.vault_meta for select to authenticated using (public.is_team_member());
create policy meta_create on public.vault_meta for insert to authenticated with check (public.is_team_admin());
create policy items_read on public.vault_items for select to authenticated using (public.is_team_member());
create policy items_insert on public.vault_items for insert to authenticated with check (public.is_team_member());
create policy items_update on public.vault_items for update to authenticated
  using (public.is_team_member()) with check (public.is_team_member());
create policy items_delete on public.vault_items for delete to authenticated using (public.is_team_member());

revoke all on public.team_members, public.team_invites, public.vault_meta, public.vault_items from anon, authenticated;
grant select on public.team_members, public.team_invites to authenticated;
grant select, insert on public.vault_meta to authenticated;
grant select, insert, update, delete on public.vault_items to authenticated;

revoke execute on all functions in schema public from public, anon;
grant execute on function public.is_team_member(), public.is_team_admin(), public.my_role(),
  public.invite_member(text, text), public.remove_member(uuid), public.cancel_invite(text),
  public.rotate_team_key(text, int, text, text, int, jsonb) to authenticated;
revoke execute on function public.handle_new_auth_user(), public.vault_items_stamp() from authenticated;
