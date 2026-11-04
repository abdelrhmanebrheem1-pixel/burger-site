
const enc = new TextEncoder();

const J = (d, s = 200, h = {}) =>
  new Response(JSON.stringify(d), {
    status: s,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...h
    }
  });

const hex = b =>
  [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');

const hmac = async (v, sec) => {
  const k = await crypto.subtle.importKey(
    'raw',
    enc.encode(sec),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(v)));
};

const sha = async s =>
  hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));

const eq = (a, b) => {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
};

const T = {
  products: ['category_id','name','description','ingredients','price','old_price','image','available','visible','featured','badge','sort','addons'],
  categories: ['name','sort'],
  offers: ['title','description','image','price','old_price','ends_at','active','product_ids']
};

const ST = ['new','preparing','delivery','done','cancelled'];

const settings = async db =>
  Object.fromEntries(
    (await db.prepare('SELECT k,v FROM settings').all()).results.map(r => [r.k, r.v])
  );

const val = v =>
  v === undefined || v === ''
    ? null
    : typeof v === 'object' && v !== null
      ? JSON.stringify(v)
      : typeof v === 'boolean'
        ? +v
        : v;

async function isAdmin(req, env) {
  const m = (req.headers.get('cookie') || '').match(/(?:^|; )s=(\d+)\.([0-9a-f]+)/);
  return !!m &&
    !!env.SESSION_SECRET &&
    +m[1] > Date.now() &&
    eq(m[2], await hmac(m[1], env.SESSION_SECRET));
}

export async function onRequest({ request: req, env, params }) {
  const p = [].concat(params.path || []);
  const m = req.method;
  const db = env.DB;

  try {
    if (p[0] === 'public' && m === 'GET') {
      const [s, c, pr, o] = await Promise.all([
        settings(db),
        db.prepare('SELECT * FROM categories ORDER BY sort,id').all(),
        db.prepare('SELECT * FROM products WHERE visible=1 ORDER BY sort,id').all(),
        db.prepare("SELECT * FROM offers WHERE active=1 AND (ends_at IS NULL OR ends_at>=date('now')) ORDER BY id DESC").all()
      ]);

      return J({
        settings: s,
        categories: c.results,
        products: pr.results,
        offers: o.results
      });
    }

    if (p[0] === 'order' && m === 'POST') {
      const b = await req.json();
      const st = await settings(db);

      const name = String(b.name || '').trim().slice(0, 80);
      const phone = String(b.phone || '').trim();
      const address = String(b.address || '').trim().slice(0, 300);

      if (
        !name ||
        !/^[0-9+\s-]{7,20}$/.test(phone) ||
        !address ||
        !Array.isArray(b.items) ||
        !b.items.length ||
        b.items.length > 50
      ) {
        return J({ error: 'بيانات الطلب غير مكتملة' }, 400);
      }

      let sub = 0;
      const items = [];

      for (const i of b.items) {
        const q = Math.min(Math.max(parseInt(i.qty) || 1, 1), 50);

        if (i.t === 'o') {
          const r = await db.prepare(
            'SELECT title AS name,price FROM offers WHERE id=? AND active=1'
          ).bind(i.id).first();

          if (!r) continue;

          sub += r.price * q;
          items.push({ name: r.name, qty: q, price: r.price, addons: [] });
        } else {
          const r = await db.prepare(
            'SELECT name,price,addons FROM products WHERE id=? AND visible=1 AND available=1'
          ).bind(i.id).first();

          if (!r) continue;

          const ad = JSON.parse(r.addons || '[]').filter(
            a => (i.addons || []).includes(a.name)
          );

          const unit = r.price + ad.reduce((x, a) => x + a.price, 0);

          sub += unit * q;
          items.push({
            name: r.name,
            qty: q,
            price: unit,
            addons: ad.map(a => a.name)
          });
        }
      }

      if (!items.length) return J({ error: 'السلة فارغة' }, 400);

      if (sub < (+st.min_order || 0)) {
        return J({ error: 'الحد الأدنى للطلب ' + st.min_order + ' ج.م' }, 400);
      }

      const del = +st.delivery_fee || 0;
      const code = 'BF-' + String(
        crypto.getRandomValues(new Uint32Array(1))[0] % 1e6
      ).padStart(6, '0');

      await db.prepare(
        'INSERT INTO orders(code,name,phone,address,notes,items,subtotal,delivery,total) VALUES(?,?,?,?,?,?,?,?,?)'
      ).bind(
        code,
        name,
        phone,
        address,
        String(b.notes || '').slice(0, 300),
        JSON.stringify(items),
        sub,
        del,
        sub + del
      ).run();

      return J({ code, total: sub + del });
    }

    if (p[0] === 'login' && m === 'POST') {
      const b = await req.json();

      if (
        !env.ADMIN_PASSWORD ||
        !env.SESSION_SECRET ||
        !eq(await sha(String(b.password || '')), await sha(env.ADMIN_PASSWORD))
      ) {
        return J({ error: 'كلمة المرور غير صحيحة' }, 401);
      }

      const exp = Date.now() + 7 * 864e5;

      return J({ ok: 1 }, 200, {
        'set-cookie': `s=${exp}.${await hmac(String(exp), env.SESSION_SECRET)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`
      });
    }

    if (p[0] === 'logout') {
      return J({ ok: 1 }, 200, {
        'set-cookie': 's=; Max-Age=0; Path=/; HttpOnly; Secure'
      });
    }

    if (p[0] !== 'admin') return J({ error: 'غير موجود' }, 404);

    if (!await isAdmin(req, env)) {
      return J({ error: 'غير مصرح' }, 401);
    }

    if (p[1] === 'upload' && m === 'POST') {
      if (!env.GITHUB_TOKEN) return J({ error: 'يلزم إعداد GITHUB_TOKEN في Cloudflare Pages Preview Secrets' }, 503);
      const type = req.headers.get('content-type') || '';
      const ext = ({ 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' })[type];
      if (!ext) return J({ error: 'ارفع JPG أو PNG أو WebP فقط' }, 415);
      const buf = await req.arrayBuffer();
      if (!buf.byteLength || buf.byteLength > 4 * 1024 * 1024) return J({ error: 'الحد الأقصى 4 ميجابايت' }, 413);
      const bytes = new Uint8Array(buf);
      const png = bytes.length >= 8 && [137,80,78,71,13,10,26,10].every((v,i)=>bytes[i]===v);
      const jpg = bytes.length >= 3 && bytes[0]===255 && bytes[1]===216 && bytes[2]===255;
      const webp = bytes.length >= 12 && String.fromCharCode(...bytes.slice(0,4))==='RIFF' && String.fromCharCode(...bytes.slice(8,12))==='WEBP';
      if (!(type==='image/png'&&png || type==='image/jpeg'&&jpg || type==='image/webp'&&webp)) return J({ error: 'نوع الملف لا يطابق محتوى الصورة' }, 415);
      let binary = '';
      for (let i=0; i<bytes.length; i+=32768) binary += String.fromCharCode(...bytes.subarray(i, Math.min(i+32768, bytes.length)));
      const path = 'public/images/' + crypto.randomUUID() + '.' + ext;
      const gh = await fetch('https://api.github.com/repos/abdelrhmanebrheem1-pixel/burger-site/contents/' + path, {
        method: 'PUT',
        headers: { 'Authorization': 'Bearer ' + env.GITHUB_TOKEN, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28' },
        body: JSON.stringify({ message: 'Upload restaurant image', content: btoa(binary), branch: 'preview-release' })
      });
      if (!gh.ok) return J({ error: gh.status===401||gh.status===403 ? 'صلاحية GitHub غير كافية؛ يلزم Contents Read and write' : 'تعذر حفظ الصورة في GitHub (' + gh.status + ')' }, 502);
      const saved = await gh.json();
      return J({ url: saved.content?.download_url || 'https://raw.githubusercontent.com/abdelrhmanebrheem1-pixel/burger-site/preview-release/' + path, path });
    }

    const id = p[2];

    if (p[1] === 'me') return J({ ok: 1 });

    if (p[1] === 'stats') {
      const o = await db.prepare(
        "SELECT COUNT(*) total,COALESCE(SUM(status='new'),0) n,COALESCE(SUM(status='done'),0) d,COALESCE(SUM(CASE WHEN status='done' THEN total END),0) sales FROM orders"
      ).first();

      const pc = await db.prepare('SELECT COUNT(*) c FROM products').first();

      return J({ ...o, products: pc.c });
    }

    if (p[1] === 'orders') {
      if (m === 'GET') {
        return J(
          (await db.prepare('SELECT * FROM orders ORDER BY id DESC LIMIT 300').all()).results
        );
      }

      if (m === 'PATCH') {
        const b = await req.json();

        if (!ST.includes(b.status)) {
          return J({ error: 'حالة غير صحيحة' }, 400);
        }

        await db.prepare('UPDATE orders SET status=? WHERE id=?')
          .bind(b.status, id).run();

        return J({ ok: 1 });
      }
    }

    if (p[1] === 'settings') {
      if (m === 'GET') return J(await settings(db));

      if (m === 'PUT') {
        const b = await req.json();
        const keys = Object.keys(await settings(db));

        await db.batch(
          keys.filter(k => k in b).map(k =>
            db.prepare('INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)')
              .bind(k, String(b[k] ?? ''))
          )
        );

        return J({ ok: 1 });
      }
    }

    const cols = T[p[1]];

    if (cols) {
      const t = p[1];
      const b = ['POST', 'PUT'].includes(m) ? await req.json() : {};
      const f = cols.filter(c => c in b);

      if (m === 'GET') {
        return J(
          (await db.prepare(
            `SELECT * FROM ${t} ORDER BY ${t === 'offers' ? 'id DESC' : 'sort,id'}`
          ).all()).results
        );
      }

      if (m === 'POST') {
        if (!f.length) return J({ error: 'بيانات غير مكتملة' }, 400);

        await db.prepare(
          `INSERT INTO ${t}(${f.join()}) VALUES(${f.map(() => '?').join()})`
        ).bind(...f.map(c => val(b[c]))).run();

        return J({ ok: 1 });
      }

      if (m === 'PUT') {
        if (!f.length) return J({ error: 'لا توجد بيانات للتعديل' }, 400);

        await db.prepare(
          `UPDATE ${t} SET ${f.map(c => c + '=?').join()} WHERE id=?`
        ).bind(...f.map(c => val(b[c])), id).run();

        return J({ ok: 1 });
      }

      if (m === 'DELETE') {
        await db.prepare(`DELETE FROM ${t} WHERE id=?`).bind(id).run();

        if (t === 'categories') {
          await db.prepare(
            'UPDATE products SET category_id=NULL WHERE category_id=?'
          ).bind(id).run();
        }

        return J({ ok: 1 });
      }
    }

    return J({ error: 'غير موجود' }, 404);

  } catch (e) {
    return J({ error: 'خطأ في الخادم' }, 500);
  }
}
