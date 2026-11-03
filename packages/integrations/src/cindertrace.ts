import {
  securityFusionInvestigationDraftSchema,
  type SecurityFusionInvestigationDraft,
} from "@cindertrace/contracts";

/** Server-side adapter for scoped agent reads and non-executable investigation drafts. */
export class CindertraceClient {
  readonly #base: string;
  readonly #readToken: string;
  readonly #draftToken: string | undefined;
  readonly #fetch: typeof fetch;
  constructor(options: {
    url: string;
    readToken: string;
    draftToken?: string;
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
    this.#fetch = options.fetchImpl ?? fetch;
  }
  async #request(
    path: string,
    draft?: SecurityFusionInvestigationDraft,
  ): Promise<unknown> {
    const token = draft ? this.#draftToken : this.#readToken;
    if (!token)
      throw new Error(
        "A separate scoped investigation-draft credential is required",
      );
    const response = await this.#fetch(this.#base + path, {
      method: draft ? "POST" : "GET",
      redirect: "error",
      signal: AbortSignal.timeout(15000),
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/json",
        ...(draft ? { "content-type": "application/json" } : {}),
      },
      ...(draft
        ? {
            body: JSON.stringify(
              securityFusionInvestigationDraftSchema.parse(draft),
            ),
          }
        : {}),
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
      draft,
    );
  }
}
