import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { Neighbors, ObjectDetail } from "../api/types";
import { mockApi, ontology, renderApp } from "../test/helpers";

const detail: ObjectDetail = {
  type: "vulnerability",
  key: "CVE-2024-10441",
  title: "Synology DSM Improper Encoding Vulnerability",
  properties: {
    name: "Synology DSM Improper Encoding Vulnerability",
    description: "Synology DiskStation Manager contains an improper encoding vulnerability.",
    kev_date_added: "2026-11-18",
    ransomware_use: "known",
    cwes: ["CWE-116"],
    cve_url: "https://www.cve.org/CVERecord?id=CVE-2024-10441",
  },
  first_seen: "2026-11-24T10:00:00+00:00",
  last_seen: "2026-11-24T16:00:00+00:00",
  provenance: [
    {
      source: {
        id: "cisa-kev",
        name: "CISA Known Exploited Vulnerabilities",
        homepage: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        licence: "CC0 1.0",
        licence_url: "https://www.cisa.gov/sites/default/files/licenses/kev/license.txt",
        attribution: "Cybersecurity and Infrastructure Security Agency (CISA)",
        redistributable: true,
      },
      fields: ["name", "description", "kev_date_added", "ransomware_use", "cwes", "cve_url"],
      first_seen: "2026-11-24T10:00:00+00:00",
      last_seen: "2026-11-24T16:00:00+00:00",
    },
  ],
};

const neighbors: Neighbors = {
  total: 1,
  items: [
    {
      link_type: "affects",
      direction: "out",
      nature: "fact",
      object: {
        type: "product",
        key: "synology:diskstation-manager-dsm",
        title: "DiskStation Manager (DSM)",
      },
    },
  ],
};

const api = {
  "/api/ontology": ontology,
  "/api/objects/vulnerability/CVE-2024-10441": detail,
  "/api/objects/vulnerability/CVE-2024-10441/neighbors": neighbors,
};

describe("object page", () => {
  it("shows what the object is", async () => {
    mockApi(api);

    renderApp("/objets/vulnerability/CVE-2024-10441");

    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "Synology DSM Improper Encoding Vulnerability",
      }),
    ).toBeVisible();
    expect(screen.getByText("CVE-2024-10441")).toBeVisible();
    expect(screen.getByText("Vulnérabilité")).toBeVisible();
  });

  it("lists its properties with the ontology's labels and readable values", async () => {
    mockApi(api);

    renderApp("/objets/vulnerability/CVE-2024-10441");

    const properties = await screen.findByRole("region", { name: "Propriétés" });
    expect(within(properties).getByText("Ajout au catalogue KEV")).toBeVisible();
    expect(within(properties).getByText("18 nov. 2026")).toBeVisible();
    expect(within(properties).getByText("Avéré")).toBeVisible();
    expect(within(properties).getByText("CWE-116")).toBeVisible();
    expect(within(properties).getByRole("link", { name: /cve\.org/ })).toHaveAttribute(
      "href",
      "https://www.cve.org/CVERecord?id=CVE-2024-10441",
    );
  });

  it("links to related objects, naming the relation", async () => {
    mockApi(api);

    renderApp("/objets/vulnerability/CVE-2024-10441");

    const links = await screen.findByRole("region", { name: "Liens" });
    const item = (await within(links).findByText("affecte")).closest("li")!;
    expect(within(item).getByText("1")).toBeVisible(); // nombre de liens de cette relation
    expect(within(item).getByRole("link", { name: "DiskStation Manager (DSM)" })).toHaveAttribute(
      "href",
      "/objets/product/synology%3Adiskstation-manager-dsm",
    );
  });

  it("shows the number a link carries, when the ontology says it has one", async () => {
    const weighted = {
      ...ontology,
      link_types: {
        ...ontology.link_types,
        affects: { ...ontology.link_types.affects!, weight: { property: "n", label: "indicateurs" } },
      },
    };
    mockApi({
      ...api,
      "/api/ontology": weighted,
      "/api/objects/vulnerability/CVE-2024-10441/neighbors": {
        total: 1,
        items: [{ ...neighbors.items[0]!, properties: { n: 1234 } }],
      },
    });

    renderApp("/objets/vulnerability/CVE-2024-10441");

    const links = await screen.findByRole("region", { name: "Liens" });
    expect(await within(links).findByText(/Produit · 1\s234 indicateurs/)).toBeVisible();
  });

  it("uses the inverse wording when the link points at this object", async () => {
    mockApi({
      "/api/ontology": ontology,
      "/api/objects/product/acme%3Arocket": {
        ...detail,
        type: "product",
        key: "acme:rocket",
        title: "Rocket",
        properties: { name: "Rocket" },
      },
      "/api/objects/product/acme%3Arocket/neighbors": {
        total: 1,
        items: [
          {
            link_type: "affects",
            direction: "in",
            nature: "fact",
            object: { type: "vulnerability", key: "CVE-2025-0002", title: "Acme Rocket Overflow" },
          },
        ],
      },
    });

    renderApp("/objets/product/acme%3Arocket");

    const links = await screen.findByRole("region", { name: "Liens" });
    expect(await within(links).findByText("est affecté par")).toBeVisible();
  });

  it("states where the data comes from and under which licence", async () => {
    mockApi(api);

    renderApp("/objets/vulnerability/CVE-2024-10441");

    const provenance = await screen.findByRole("complementary", { name: "Provenance" });
    expect(
      within(provenance).getByRole("link", { name: "CISA Known Exploited Vulnerabilities" }),
    ).toHaveAttribute("href", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
    expect(within(provenance).getByRole("link", { name: "CC0 1.0" })).toHaveAttribute(
      "href",
      "https://www.cisa.gov/sites/default/files/licenses/kev/license.txt",
    );
    expect(within(provenance).getByText(/24 nov\. 2026/)).toBeVisible();
  });

  it("says so when the object does not exist", async () => {
    mockApi({ "/api/ontology": ontology });

    renderApp("/objets/vulnerability/CVE-1999-0000");

    expect(await screen.findByText(/Cet objet n'existe pas/)).toBeVisible();
  });
});
