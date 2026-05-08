import { z } from "zod";

const EnvSchema = z.object({
  DATABASE_URL: z.string().min(1),
  NEO4J_URI: z.string().min(1),
  NEO4J_USER: z.string().min(1),
  NEO4J_PASSWORD: z.string().min(1),

  /**
   * MCP recon system: Ollama configuration.
   * Models can be overridden via env; defaults match the design doc:
   *   manager:    qwen3:8b
   *   specialist: qwen3:8b
   *   prompter:   qwen3:8b
   */
  OLLAMA_URL: z.string().min(1).default("http://localhost:11434"),
  OLLAMA_MANAGER_MODEL: z.string().min(1).default("qwen3:8b"),
  OLLAMA_SPECIALIST_MODEL: z.string().min(1).default("qwen3:8b"),
  OLLAMA_PROMPTER_MODEL: z.string().min(1).default("qwen3:8b"),
  RECON_MAX_STEPS: z.coerce.number().int().positive().default(20),

  /** Legacy classic-scan settings (still used by the deterministic nmap pipeline). */
  HYDRA_ENABLED: z.coerce.boolean().default(false),
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

  /**
   * All tool execution (nmap, smbclient, openssl, curl, gobuster, dig, ...) goes
   * over SSH to this host. The worker container only runs Node + DB clients.
   */
  REMOTE_SSH_HOST: z
    .string()
    .transform((s) => s.trim())
    .pipe(z.string().min(1, "REMOTE_SSH_HOST is required — all tools run over SSH")),
  REMOTE_SSH_USER: z
    .string()
    .transform((s) => s.trim())
    .pipe(z.string().min(1, "REMOTE_SSH_USER is required")),
  REMOTE_SSH_PORT: z.coerce.number().default(22),
  REMOTE_SSH_PASSWORD: z.string().optional(),
  REMOTE_SSH_IDENTITY_FILE: z.string().optional(),
  REMOTE_SSH_STRICT_HOST_KEY_CHECKING: z.enum(["yes", "no", "accept-new"]).default("accept-new")
}).superRefine((data, ctx) => {
  const hasKey = Boolean(data.REMOTE_SSH_IDENTITY_FILE?.trim());
  const hasPass = Boolean(data.REMOTE_SSH_PASSWORD && data.REMOTE_SSH_PASSWORD.length > 0);
  if (!hasKey && !hasPass) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Set REMOTE_SSH_IDENTITY_FILE or REMOTE_SSH_PASSWORD for non-interactive SSH",
      path: ["REMOTE_SSH_PASSWORD"]
    });
  }
});

export const env = EnvSchema.parse(process.env);
