// Vercel version of /api/config: serves the public Supabase settings from
// environment variables. Table access is protected by Row Level Security.
export default function handler(req, res) {
  res.setHeader("cache-control", "public, max-age=300");
  res.status(200).json({
    url: process.env.SUPABASE_URL || "",
    anonKey: process.env.SUPABASE_ANON_KEY || "",
  });
}
