-- خضار مكة — online orders for a vegetable shop.
-- Lives in the musaed-support Supabase project (tables prefixed shop_), separate from support_*.
-- Tables have RLS on, no policies and no grants to anon/authenticated: the pages only call the
-- security-definer functions below. Admin functions check the shop password (bcrypt hash in
-- shop_settings.admin_hash; set it with:  update shop_settings set admin_hash = extensions.crypt('PASS', extensions.gen_salt('bf')) where id = 1;)

create table if not exists shop_settings (
  id int primary key default 1 check (id = 1),
  shop_name text not null default 'خضار مكة',
  phone text not null default '',
  delivery_fee numeric(10,2) not null default 10,
  min_order numeric(10,2) not null default 50,
  is_open boolean not null default true,
  closed_note text not null default '',
  admin_hash text not null default '',
  updated_at timestamptz not null default now()
);
insert into shop_settings (id) values (1) on conflict do nothing;

create table if not exists shop_products (
  id bigint generated always as identity primary key,
  name text not null check (length(name) between 1 and 60),
  category text not null default 'خضار',
  unit text not null default 'كيلو',          -- كيلو / حزمة / واحدة
  step numeric(6,2) not null default 0.5 check (step > 0),
  price numeric(10,2) not null default 0 check (price >= 0),
  available boolean not null default false,
  image_url text not null default '',
  sort int not null default 100,
  updated_at timestamptz not null default now()
);

create table if not exists shop_orders (
  id bigint generated always as identity primary key,
  token uuid not null default gen_random_uuid() unique,
  created_at timestamptz not null default now(),
  name text not null,
  phone text not null,
  address text not null,
  note text not null default '',
  items jsonb not null,                        -- [{id,name,unit,qty,price,line}]
  subtotal numeric(10,2) not null,
  delivery_fee numeric(10,2) not null,
  total numeric(10,2) not null,
  status text not null default 'new' check (status in ('new','preparing','sent','cancelled')),
  status_at timestamptz not null default now()
);
create index if not exists shop_orders_status_idx on shop_orders (status, created_at desc);
create index if not exists shop_orders_phone_idx on shop_orders (phone, created_at desc);

create table if not exists shop_admin_fail (at timestamptz not null default now());

alter table shop_settings enable row level security;
alter table shop_products enable row level security;
alter table shop_orders enable row level security;
alter table shop_admin_fail enable row level security;
revoke all on shop_settings, shop_products, shop_orders, shop_admin_fail from anon, authenticated;

-- ---------- public (customer) ----------

create or replace function shop_catalog() returns jsonb
language sql security definer set search_path = public stable as $$
  select jsonb_build_object(
    'settings', (select jsonb_build_object('shop_name', shop_name, 'phone', phone, 'delivery_fee', delivery_fee,
                  'min_order', min_order, 'is_open', is_open, 'closed_note', closed_note) from shop_settings where id = 1),
    'products', coalesce((select jsonb_agg(jsonb_build_object('id', id, 'name', name, 'category', category, 'unit', unit,
                  'step', step, 'price', price, 'image_url', image_url) order by sort, name)
                  from shop_products where available and price > 0), '[]'::jsonb));
$$;

create or replace function shop_place_order(p_items jsonb, p_name text, p_phone text, p_address text, p_note text default '')
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  s shop_settings; it jsonb; p shop_products; q numeric; lines jsonb := '[]'::jsonb; sub numeric := 0; o shop_orders;
begin
  select * into s from shop_settings where id = 1;
  if not s.is_open then raise exception 'المحل قافل دلوقتي'; end if;
  p_name := btrim(coalesce(p_name, '')); p_phone := regexp_replace(coalesce(p_phone, ''), '\D', '', 'g');
  p_address := btrim(coalesce(p_address, '')); p_note := left(btrim(coalesce(p_note, '')), 300);
  if length(p_name) < 2 or length(p_name) > 60 then raise exception 'اكتب اسمك'; end if;
  if p_phone !~ '^01[0-9]{9}$' then raise exception 'رقم الموبايل لازم يكون ١١ رقم ويبدأ بـ 01'; end if;
  if length(p_address) < 5 or length(p_address) > 200 then raise exception 'اكتب العنوان بالتفصيل'; end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) = 0 or jsonb_array_length(p_items) > 60 then
    raise exception 'السلة فاضية'; end if;
  if (select count(*) from shop_orders where phone = p_phone and created_at > now() - interval '1 hour') >= 6 then
    raise exception 'طلبات كتير من نفس الرقم، كلّم المحل'; end if;
  for it in select * from jsonb_array_elements(p_items) loop
    select * into p from shop_products where id = (it->>'id')::bigint;
    if not found or not p.available or p.price <= 0 then
      raise exception 'صنف في السلة مبقاش متوفر، ارجع للمحل وحدّث السلة'; end if;
    q := (it->>'qty')::numeric;
    if q is null or q <= 0 or q > 50 or mod(q, p.step) <> 0 then raise exception 'كمية غلط في %', p.name; end if;
    lines := lines || jsonb_build_object('id', p.id, 'name', p.name, 'unit', p.unit, 'qty', q, 'price', p.price, 'line', round(q * p.price, 2));
    sub := sub + round(q * p.price, 2);
  end loop;
  if sub < s.min_order then raise exception 'أقل طلب % جنيه', s.min_order; end if;
  insert into shop_orders (name, phone, address, note, items, subtotal, delivery_fee, total)
  values (p_name, p_phone, p_address, p_note, lines, sub, s.delivery_fee, sub + s.delivery_fee) returning * into o;
  return jsonb_build_object('id', o.id, 'token', o.token, 'subtotal', o.subtotal, 'delivery_fee', o.delivery_fee, 'total', o.total);
end $$;

create or replace function shop_order_status(p_token uuid) returns jsonb
language sql security definer set search_path = public stable as $$
  select jsonb_build_object('id', id, 'status', status, 'created_at', created_at, 'items', items,
    'subtotal', subtotal, 'delivery_fee', delivery_fee, 'total', total)
  from shop_orders where token = p_token;
$$;

-- ---------- admin (shop owner, password) ----------

create or replace function shop_auth(p_pass text) returns boolean
language plpgsql security definer set search_path = public as $$
declare h text;
begin
  if (select count(*) from shop_admin_fail where at > now() - interval '15 minutes') >= 30 then return false; end if;
  select admin_hash into h from shop_settings where id = 1;
  if h <> '' and p_pass is not null and extensions.crypt(p_pass, h) = h then return true; end if;
  insert into shop_admin_fail default values;
  delete from shop_admin_fail where at < now() - interval '1 day';
  return false;
end $$;

create or replace function shop_admin_login(p_pass text) returns boolean
language sql security definer set search_path = public as $$ select shop_auth(p_pass); $$;

create or replace function shop_admin_data(p_pass text) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not shop_auth(p_pass) then return jsonb_build_object('error', 'auth'); end if;
  return jsonb_build_object(
    'settings', (select to_jsonb(s) - 'admin_hash' from shop_settings s where id = 1),
    'products', coalesce((select jsonb_agg(to_jsonb(p) order by p.sort, p.name) from shop_products p), '[]'::jsonb),
    'orders', coalesce((select jsonb_agg(to_jsonb(o) - 'token' order by o.created_at desc) from shop_orders o
               where o.status in ('new','preparing') or o.created_at > now() - interval '3 days'), '[]'::jsonb));
end $$;

create or replace function shop_admin_set_status(p_pass text, p_id bigint, p_status text) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not shop_auth(p_pass) then return jsonb_build_object('error', 'auth'); end if;
  update shop_orders set status = p_status, status_at = now() where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function shop_admin_save_product(p_pass text, p jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare rid bigint;
begin
  if not shop_auth(p_pass) then return jsonb_build_object('error', 'auth'); end if;
  if (p->>'id') is null then
    insert into shop_products (name, category, unit, step, price, available, image_url, sort)
    values (btrim(p->>'name'), coalesce(p->>'category', 'خضار'), coalesce(p->>'unit', 'كيلو'),
            coalesce((p->>'step')::numeric, 0.5), coalesce((p->>'price')::numeric, 0),
            coalesce((p->>'available')::boolean, false), coalesce(p->>'image_url', ''), coalesce((p->>'sort')::int, 100))
    returning id into rid;
  else
    rid := (p->>'id')::bigint;
    update shop_products set
      name = coalesce(btrim(p->>'name'), name), category = coalesce(p->>'category', category),
      unit = coalesce(p->>'unit', unit), step = coalesce((p->>'step')::numeric, step),
      price = coalesce((p->>'price')::numeric, price), available = coalesce((p->>'available')::boolean, available),
      image_url = coalesce(p->>'image_url', image_url), sort = coalesce((p->>'sort')::int, sort), updated_at = now()
    where id = rid;
  end if;
  return jsonb_build_object('ok', true, 'id', rid);
end $$;

create or replace function shop_admin_delete_product(p_pass text, p_id bigint) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not shop_auth(p_pass) then return jsonb_build_object('error', 'auth'); end if;
  delete from shop_products where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function shop_admin_save_settings(p_pass text, s jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not shop_auth(p_pass) then return jsonb_build_object('error', 'auth'); end if;
  update shop_settings set
    shop_name = coalesce(nullif(btrim(s->>'shop_name'), ''), shop_name), phone = coalesce(s->>'phone', phone),
    delivery_fee = coalesce((s->>'delivery_fee')::numeric, delivery_fee), min_order = coalesce((s->>'min_order')::numeric, min_order),
    is_open = coalesce((s->>'is_open')::boolean, is_open), closed_note = coalesce(s->>'closed_note', closed_note),
    admin_hash = case when length(coalesce(s->>'new_password', '')) >= 6
                      then extensions.crypt(s->>'new_password', extensions.gen_salt('bf')) else admin_hash end,
    updated_at = now()
  where id = 1;
  return jsonb_build_object('ok', true);
end $$;

-- Only the RPCs are callable from the pages.
revoke execute on function shop_auth(text) from public, anon, authenticated;
grant execute on function shop_catalog(), shop_place_order(jsonb, text, text, text, text), shop_order_status(uuid),
  shop_admin_login(text), shop_admin_data(text), shop_admin_set_status(text, bigint, text),
  shop_admin_save_product(text, jsonb), shop_admin_delete_product(text, bigint), shop_admin_save_settings(text, jsonb)
  to anon, authenticated;

-- Product photos: public bucket; uploads only through the shop-upload Edge Function (checks the password).
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('shop-products', 'shop-products', true, 1048576, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

-- Starter list (no prices; the owner sets a price and the item shows up).
insert into shop_products (name, category, unit, step, sort)
select * from (values
  ('طماطم','خضار','كيلو',0.5,1),('خيار','خضار','كيلو',0.5,2),('بطاطس','خضار','كيلو',0.5,3),('بصل أحمر','خضار','كيلو',0.5,4),
  ('بصل أبيض','خضار','كيلو',0.5,5),('ثوم','خضار','كيلو',0.25,6),('فلفل رومي','خضار','كيلو',0.5,7),('فلفل حامي','خضار','كيلو',0.25,8),
  ('كوسة','خضار','كيلو',0.5,9),('باذنجان رومي','خضار','كيلو',0.5,10),('باذنجان أبيض','خضار','كيلو',0.5,11),('جزر','خضار','كيلو',0.5,12),
  ('بطاطا','خضار','كيلو',0.5,13),('قرنبيط','خضار','واحدة',1,14),('كرنب','خضار','واحدة',1,15),('ليمون','خضار','كيلو',0.25,16),
  ('بقدونس','ورقيات وخضرة','حزمة',1,20),('شبت','ورقيات وخضرة','حزمة',1,21),('كزبرة','ورقيات وخضرة','حزمة',1,22),
  ('جرجير','ورقيات وخضرة','حزمة',1,23),('خس','ورقيات وخضرة','واحدة',1,24),('نعناع','ورقيات وخضرة','حزمة',1,25),
  ('بصل أخضر','ورقيات وخضرة','حزمة',1,26),('ملوخية','ورقيات وخضرة','كيلو',0.5,27),('سبانخ','ورقيات وخضرة','كيلو',0.5,28),
  ('برتقال','فاكهة','كيلو',0.5,40),('يوسفي','فاكهة','كيلو',0.5,41),('موز','فاكهة','كيلو',0.5,42),('تفاح','فاكهة','كيلو',0.5,43),
  ('جوافة','فاكهة','كيلو',0.5,44),('رمان','فاكهة','كيلو',0.5,45)
) v(name, category, unit, step, sort)
where not exists (select 1 from shop_products);
