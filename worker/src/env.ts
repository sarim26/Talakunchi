import { z } from "zod";

const EnvSchema = z.object({
  DATABASE_URL: z.string().min(1),
  NEO4J_URI: z.string().min(1),
  NEO4J_USER: z.string().min(1),
  NEO4J_PASSWORD: z.string().min(1),

  /**
   * MCP recon system: Ollama configuration.
   * - manager: step planner
   * - prompter: intent → specialist-facing prose
   * - specialist: default model for the post-prompter **execution command writer**
   *   (structured args) when `OLLAMA_COMMAND_WRITER_MODEL` is not set
   * - command_writer: optional override for that same writer step only
   */
  OLLAMA_URL: z.string().min(1).default("http://localhost:11434"),
  OLLAMA_MANAGER_MODEL: z.string().min(1).default("deepseek-r1:14b"),
  OLLAMA_SPECIALIST_MODEL: z.string().min(1).default("qwen2.5-coder:7b"),
  OLLAMA_PROMPTER_MODEL: z.string().min(1).default("qwen3:14b"),
  /**
   * Optional model for turning `web_path` / `web_url` facts into security findings
   * (replaces static keyword lists). Defaults to `OLLAMA_SPECIALIST_MODEL`.
   */
  OLLAMA_WEB_FINDINGS_MODEL: z.preprocess(
    (v) => (typeof v === "string" && v.trim() === "" ? undefined : v),
    z.string().min(1).optional()
  ),
  /**
   * Optional override for the execution-command-writer LLM. If unset or empty,
   * `OLLAMA_SPECIALIST_MODEL` is used (see `env.executionWriterModel`).
   */
  OLLAMA_COMMAND_WRITER_MODEL: z.preprocess(
    (v) => (typeof v === "string" && v.trim() === "" ? undefined : v),
    z.string().min(1).optional()
  ),
  RECON_MAX_STEPS: z.coerce.number().int().positive().default(20),

  /** Legacy classic-scan settings (non-MCP pipeline). */
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
  /** Optional sudo password for the remote Kali user (used by system.tool_installer). */
  REMOTE_SSH_SUDO_PASSWORD: z.string().optional(),
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

const _parsed = EnvSchema.parse(process.env);

/** Effective model for `executionCommandWriter` (arg filling after prompter). */
export const env = {
  ..._parsed,
  get executionWriterModel(): string {
    return _parsed.OLLAMA_COMMAND_WRITER_MODEL ?? _parsed.OLLAMA_SPECIALIST_MODEL;
  },
  get webFindingsModel(): string {
    return _parsed.OLLAMA_WEB_FINDINGS_MODEL ?? _parsed.OLLAMA_SPECIALIST_MODEL;
  }
};
