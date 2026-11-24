import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { SourceStatus, Stats } from "../api/types";
import { mockApi, ontology, renderApp } from "../test/helpers";

const stats: Stats = { objects: { vulnerability: 1792, product: 753 }, links: 2545 };

const sources: SourceStatus[] = [
  {
    id: "cisa-kev",
    name: "CISA Known Exploited Vulnerabilities",
    homepage: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    licence: "CC0 1.0",
    licence_url: "https://www.cisa.gov/sites/default/files/licenses/kev/license.txt",
    attribution: "Cybersecurity and Infrastructure Security Agency (CISA)",
    redistributable: true,
    objects_count: 2844,
    last_run: {
      id: 3,
      source_id: "cisa-kev",
      mode: "live",
      status: "success",
      started_at: "2026-11-24T10:00:00+00:00",
      finished_at: "2026-11-24T10:00:02+00:00",
      objects_count: 2844,
      links_count: 2545,
      skipped_count: 0,
      error: null,
    },
  },
];

const api = { "/api/ontology": ontology, "/api/stats": stats, "/api/sources": sources };

describe("home", () => {
  it("counts the objects of each type and links to their list", async () => {
    mockApi(api);

    renderApp("/");

    const menace = await screen.findByRole("region", { name: "Menace" });
    const link = await within(menace).findByRole("link", { name: /Vulnérabilités/ });
    expect(link).toHaveAttribute("href", "/objets/vulnerability");
    expect(link).toHaveTextContent(/1\s792/);
    expect(within(menace).getByRole("link", { name: /Produits/ })).toHaveTextContent("753");
  });

  it("says which layers hold no data yet", async () => {
    mockApi(api);

    renderApp("/");

    const territoire = await screen.findByRole("region", { name: "Territoire" });
    expect(within(territoire).getByText(/Encore sous l'eau/)).toBeVisible();
  });

  it("reports the state of each source", async () => {
    mockApi(api);

    renderApp("/sources");

    const row = (await screen.findByText("CISA Known Exploited Vulnerabilities")).closest("tr")!;
    expect(within(row).getByText("CC0 1.0")).toBeVisible();
    expect(within(row).getByText(/Collecte réussie/)).toBeVisible();
    expect(within(row).getByText(/24 nov\. 2026/)).toBeVisible();
  });

  it("shows why a collection failed", async () => {
    const failed = {
      ...sources[0]!,
      last_run: { ...sources[0]!.last_run!, status: "failed" as const, error: "HTTP 503" },
    };
    mockApi({ ...api, "/api/sources": [failed] });

    renderApp("/sources");

    const row = (await screen.findByText("CISA Known Exploited Vulnerabilities")).closest("tr")!;
    expect(within(row).getByText(/Échec/)).toBeVisible();
    expect(within(row).getByText(/HTTP 503/)).toBeVisible();
  });
});
