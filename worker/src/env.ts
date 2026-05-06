import { z } from "zod";

const EnvSchema = z.object({
  DATABASE_URL: z.string().min(1),
  NEO4J_URI: z.string().min(1),
  NEO4J_USER: z.string().min(1),
  NEO4J_PASSWORD: z.string().min(1),
  SCAN_MODE: z.enum(["nmap", "agent"]).default("nmap"),
  AGENT_ENABLED: z.coerce.boolean().default(true),
  GEMINI_API_KEY: z.string().optional(),
  GEMINI_MODEL: z.string().optional().default("gemini-3.1-flash-lite-preview"),
  AGENT_MAX_STEPS: z.coerce.number().default(30),
  AGENT_SCOPE: z.string().optional().default(""),
  HYDRA_ENABLED: z.coerce.boolean().default(true),
  HYDRA_USERNAME: z.string().optional(),
  HYDRA_PASSWORD: z.string().optional(),
  HYDRA_USERLIST: z.string().optional(),
  HYDRA_PASSLIST: z.string().optional(),
  HYDRA_STOP_ON_FIRST_FIND: z.coerce.boolean().default(false),
  HYDRA_THREADS: z.coerce.number().optional(),
  NMAP_ARGS: z
    .string()
    .optional()
    .default("-Pn -vvv --reason --stats-every 5s -sV --version-light --top-ports 200"),
  POLL_INTERVAL_MS: z.coerce.number().default(1500),
  EXPLOIT_ENABLED: z.coerce.boolean().default(true),
  EXPLOIT_MAX_STEPS: z.coerce.number().default(15),
  EXPLOIT_LHOST_ALLOWLIST: z.string().optional().default("")
});

export const env = EnvSchema.parse(process.env);

