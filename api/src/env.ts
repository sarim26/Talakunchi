import { z } from "zod";

const EnvSchema = z.object({
  PORT: z.coerce.number().default(8080),
  DATABASE_URL: z.string().min(1),
  NEO4J_URI: z.string().min(1),
  NEO4J_USER: z.string().min(1),
  NEO4J_PASSWORD: z.string().min(1),
  /** AI provider — Ollama only. Kept for compatibility with /api/ai/models clients. */
  // Back-compat: some existing .env files may still set AI_MODE=gemini.
  // We no longer support Gemini; treat it as "ollama" to keep the API booting.
  AI_MODE: z
    .enum(["mock", "ollama", "gemini"])
    .default("ollama")
    .transform((v) => (v === "gemini" ? "ollama" : v)),
  OLLAMA_URL: z.string().min(1).default("http://localhost:11434"),
  /** Finding explain, agent-run AI summary, and detailed AI report. */
  OLLAMA_EXPLAIN_MODEL: z.string().min(1).default("qwen3:14b")
});

export type Env = z.infer<typeof EnvSchema>;

export const env: Env = EnvSchema.parse(process.env);
