// Sirve el sitio estático (docs/) y añade soporte de Range (HTTP 206) para los
// vídeos, servidos por la ruta /media/<archivo> → asset docs/img/<archivo>.
// Necesario porque Safari/iOS no reproducen <video> sin respuestas de rango.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/media/")) {
      const name = url.pathname.slice("/media/".length);
      if (!/^[a-zA-Z0-9._-]+$/.test(name)) return new Response("bad name", { status: 400 });
      const assetURL = new URL("/img/" + name, url.origin);
      const res = await env.ASSETS.fetch(new Request(assetURL));
      if (res.status !== 200) return res;

      const buf = await res.arrayBuffer();
      const total = buf.byteLength;
      const headers = new Headers(res.headers);
      headers.set("Accept-Ranges", "bytes");
      headers.set("Cache-Control", "public, max-age=86400");

      const range = request.headers.get("Range");
      if (!range) {
        headers.set("Content-Length", String(total));
        return new Response(buf, { status: 200, headers });
      }
      const m = /^bytes=(\d*)-(\d*)/.exec(range);
      if (!m) { headers.set("Content-Length", String(total)); return new Response(buf, { status: 200, headers }); }
      let start = m[1] === "" ? NaN : parseInt(m[1], 10);
      let end   = m[2] === "" ? NaN : parseInt(m[2], 10);
      if (Number.isNaN(start)) { const n = Number.isNaN(end) ? 0 : end; start = Math.max(0, total - n); end = total - 1; }
      else if (Number.isNaN(end)) { end = total - 1; }
      end = Math.min(end, total - 1);
      if (start > end || start >= total) {
        return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${total}`, "Accept-Ranges": "bytes" } });
      }
      headers.set("Content-Range", `bytes ${start}-${end}/${total}`);
      headers.set("Content-Length", String(end - start + 1));
      return new Response(buf.slice(start, end + 1), { status: 206, headers });
    }

    return env.ASSETS.fetch(request);
  },
};
