import { z } from "zod";
const EnvSchema = z.object({
    PORT: z.coerce.number().default(8080),
    DATABASE_URL: z.string().min(1),
    NEO4J_URI: z.string().min(1),
    NEO4J_USER: z.string().min(1),
    NEO4J_PASSWORD: z.string().min(1),
    AI_MODE: z.enum(["mock"]).default("mock")
});
export const env = EnvSchema.parse(process.env);
