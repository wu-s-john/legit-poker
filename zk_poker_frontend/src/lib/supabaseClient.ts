import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { env } from '~/env';

let cachedClient: SupabaseClient | null = null;

export interface ConfigureSupabaseOptions {
  client?: SupabaseClient;
}

export function configureSupabaseClient(options: ConfigureSupabaseOptions = {}): SupabaseClient {
  cachedClient = options.client ?? createClient(env.NEXT_PUBLIC_SUPABASE_URL, env.NEXT_PUBLIC_SUPABASE_ANON_KEY);
  return cachedClient;
}

export function getSupabaseClient(): SupabaseClient {
  if (cachedClient) {
    return cachedClient;
  }

  return configureSupabaseClient();
}
