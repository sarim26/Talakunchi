import { type Session } from "neo4j-driver";
import { withClient } from "./db.js";
import { withSession } from "./neo4j.js";

export async function upsertNeo4jTarget(target: { id: string; name: string; address: string }) {
  await withSession(async (s) => {
    await s.run(
      `
      merge (t:Target {id: $id})
      set t.name = $name, t.address = $address
      `,
      { id: target.id, name: target.name, address: target.address }
    );
  });
}

async function clearTargetSubgraph(s: Session, targetId: string) {
  await s.run(
    `
    match (t:Target {id: $targetId})-[:HAS_SERVICE]->(svc:Service)
    optional match (svc)-[:HAS_FINDING]->(f:Finding)
    detach delete f
    `,
    { targetId }
  );
  await s.run(
    `
    match (t:Target {id: $targetId})-[:HAS_SERVICE]->(svc:Service)
    detach delete svc
    `,
    { targetId }
  );
  await s.run(
    `
    match (t:Target {id: $targetId})-[:HAS_FINDING]->(f:Finding)
    detach delete f
    `,
    { targetId }
  );
}

/** Rebuild Neo4j Target → Service / Finding graph from current Postgres rows for the target. */
export async function rebuildNeo4jForTarget(targetId: string) {
  const data = await withClient(async (c) => {
    const tRes = await c.query(`select id, name, address from targets where id = $1`, [targetId]);
    const sRes = await c.query(
      `select id, port, protocol, service_name, product, version from services where target_id = $1`,
      [targetId]
    );
    const fRes = await c.query(
      `select id, service_id, title, severity, status from findings where target_id = $1`,
      [targetId]
    );
    return { target: tRes.rows[0], services: sRes.rows, findings: fRes.rows };
  });

  const row = data.target as { id: string; name: string; address: string } | undefined;
  if (!row?.id) return;

  await withSession(async (s) => {
    await clearTargetSubgraph(s, row.id);

    await s.run(`merge (t:Target {id: $id}) set t.name=$name, t.address=$address`, {
      id: row.id,
      name: row.name,
      address: row.address
    });

    for (const svc of data.services as Array<{
      id: string;
      port: number;
      protocol: string;
      service_name: string | null;
      product: string | null;
      version: string | null;
    }>) {
      await s.run(
        `
        merge (svc:Service {id: $id})
        set svc.port=$port, svc.protocol=$protocol, svc.name=$name, svc.product=$product, svc.version=$version
        with svc
        match (t:Target {id: $targetId})
        merge (t)-[:HAS_SERVICE]->(svc)
        `,
        {
          id: svc.id,
          targetId: row.id,
          port: svc.port,
          protocol: svc.protocol,
          name: svc.service_name ?? "",
          product: svc.product ?? "",
          version: svc.version ?? ""
        }
      );
    }

    for (const f of data.findings as Array<{
      id: string;
      service_id: string | null;
      title: string;
      severity: string;
      status: string;
    }>) {
      await s.run(
        `
        merge (fn:Finding {id: $id})
        set fn.title=$title, fn.severity=$severity, fn.status=$status
        `,
        { id: f.id, title: f.title, severity: f.severity, status: f.status }
      );

      if (f.service_id) {
        await s.run(
          `
          match (svc:Service {id: $svcId})
          match (fn:Finding {id: $findingId})
          merge (svc)-[:HAS_FINDING]->(fn)
          `,
          { svcId: f.service_id, findingId: f.id }
        );
      } else {
        await s.run(
          `
          match (t:Target {id: $targetId})
          match (fn:Finding {id: $findingId})
          merge (t)-[:HAS_FINDING]->(fn)
          `,
          { targetId: row.id, findingId: f.id }
        );
      }
    }
  });
}
