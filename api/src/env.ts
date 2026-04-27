import { z } from "zod";

const EnvSchema = z.object({
  PORT: z.coerce.number().default(8080),
  DATABASE_URL: z.string().min(1),
  NEO4J_URI: z.string().min(1),
  NEO4J_USER: z.string().min(1),
  NEO4J_PASSWORD: z.string().min(1),
  AI_MODE: z.enum(["mock", "gemini"]).default("mock"),
  GEMINI_API_KEY: z.string().optional(),
  // Default to a commonly-available alias; can be overridden via .env
  GEMINI_MODEL: z.string().optional().default("gemini-1.5-flash-latest")
});

export type Env = z.infer<typeof EnvSchema>;

export const env: Env = EnvSchema.parse(process.env);

