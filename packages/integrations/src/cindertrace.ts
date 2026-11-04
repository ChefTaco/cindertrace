import {
  labRunSchema, labComparisonSchema, labTransitionSchema, labStatusSchema,
  type LabTransition,
  securityFusionInvestigationDraftSchema,
  type SecurityFusionInvestigationDraft,
} from "@cindertrace/contracts";

/** Server-side adapter for scoped agent reads and non-executable investigation drafts. */
export class CindertraceClient {
  readonly #base: string;
  readonly #readToken: string;
  readonly #draftToken: string | undefined;
  readonly #labControlToken: string | undefined;
  readonly #fetch: typeof fetch;
  constructor(options: {
    url: string;
    readToken: string;
    draftToken?: string;
    labControlToken?: string;
    fetchImpl?: typeof fetch;
  }) {
    const url = new URL(options.url);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      !options.readToken
    )
      throw new Error(
        "Cindertrace requires HTTPS and a scoped read credential",
      );
    this.#base = url.href.replace(/\/$/, "") + "/api/v1/security-fusion";
    this.#readToken = options.readToken;
    this.#draftToken = options.draftToken;
    this.#labControlToken = options.labControlToken;
    this.#fetch = options.fetchImpl ?? fetch;
  }
  async #request(
    path: string,
    body?: unknown,
    scope: "draft" | "lab-control" = "draft",
  ): Promise<unknown> {
    const token = body === undefined ? this.#readToken : scope === "lab-control" ? this.#labControlToken : this.#draftToken;
    if (!token)
      throw new Error(
        scope === "lab-control" ? "A separate scoped lab-control credential is required" : "A separate scoped investigation-draft credential is required",
      );
    const response = await this.#fetch(this.#base + path, {
      method: body === undefined ? "GET" : "POST",
      redirect: "error",
      signal: AbortSignal.timeout(15000),
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`Cindertrace HTTP ${response.status}`);
    }
    const reader = response.body?.getReader();
    if (!reader) throw new Error("Missing Cindertrace response");
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    try {
      for (;;) {
        const row = await reader.read();
        if (row.done) break;
        bytes += row.value.length;
        if (bytes > 2_000_000)
          throw new Error("Cindertrace response limit exceeded");
        chunks.push(row.value);
      }
    } finally {
      await reader.cancel();
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  }
  async lab() {
    const result = await this.#request("/lab") as {data: unknown};
    return labStatusSchema.parse(result.data);
  }
  async labRun(id: string) {
    const result = await this.#request("/lab/runs/" + encodeURIComponent(id)) as { data: unknown };
    return labRunSchema.parse(result.data);
  }
  advanceLab(id: string, transition: LabTransition) {
    return this.#request("/lab/runs/" + encodeURIComponent(id) + "/advance", labTransitionSchema.parse(transition), "lab-control");
  }
  completeLab(id: string, transition: LabTransition) {
    return this.#request("/lab/runs/" + encodeURIComponent(id) + "/complete", labTransitionSchema.parse(transition), "lab-control");
  }
  async compareLab(id: string) {
    const result = await this.#request("/lab/runs/" + encodeURIComponent(id) + "/comparison") as { data: unknown };
    return labComparisonSchema.parse(result.data);
  }
  overview() {
    return this.#request("/overview");
  }
  cases() {
    return this.#request("/cases");
  }
  case(id: string) {
    if (!id || id.length > 160) throw new Error("Invalid case identity");
    return this.#request("/cases/" + encodeURIComponent(id));
  }
  events() {
    return this.#request("/events");
  }
  entities() {
    return this.#request("/entities");
  }
  sources() {
    return this.#request("/sources");
  }
  draftInvestigation(id: string, draft: SecurityFusionInvestigationDraft) {
    if (!id || id.length > 160) throw new Error("Invalid case identity");
    return this.#request(
      "/cases/" + encodeURIComponent(id) + "/investigations",
      securityFusionInvestigationDraftSchema.parse(draft),
    );
  }
}
