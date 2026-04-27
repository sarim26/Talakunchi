import pg from "pg";
import { env } from "./env.js";
export const pool = new pg.Pool({
    connectionString: env.DATABASE_URL
});
export async function withClient(fn) {
    const client = await pool.connect();
    try {
        return await fn(client);
    }
    finally {
        client.release();
    }
}
