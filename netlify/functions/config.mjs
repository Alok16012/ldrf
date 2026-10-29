// Serves the public Supabase settings from Netlify environment variables.
// Only the URL and the public "anon" key are exposed — table access is
// restricted by Row Level Security (see supabase/schema.sql).
export default async () =>
  new Response(
    JSON.stringify({
      url: process.env.SUPABASE_URL || "",
      anonKey: process.env.SUPABASE_ANON_KEY || "",
    }),
    { headers: { "content-type": "application/json", "cache-control": "public, max-age=300" } }
  );

export const config = { path: "/api/config" };
