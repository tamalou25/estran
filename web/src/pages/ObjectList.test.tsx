import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { ObjectPage } from "../api/types";
import { mockApi, ontology, renderApp } from "../test/helpers";

const page: ObjectPage = {
  total: 2,
  page: 1,
  size: 50,
  items: [
    {
      type: "vulnerability",
      key: "CVE-2024-10441",
      title: "Synology DSM Improper Encoding Vulnerability",
      properties: { kev_date_added: "2026-11-18", ransomware_use: "known" },
      first_seen: "2026-11-24T10:00:00+00:00",
      last_seen: "2026-11-24T10:00:00+00:00",
    },
    {
      type: "vulnerability",
      key: "CVE-2026-41709",
      title: "Broadcom VMware ESX Insufficient Logging Vulnerability",
      properties: { kev_date_added: "2026-10-28", ransomware_use: "unknown" },
      first_seen: "2026-11-24T10:00:00+00:00",
      last_seen: "2026-11-24T10:00:00+00:00",
    },
  ],
};

describe("object list", () => {
  it("builds its heading and columns from the ontology", async () => {
    mockApi({ "/api/ontology": ontology, "/api/objects": page });

    renderApp("/objets/vulnerability");

    expect(await screen.findByRole("heading", { level: 1, name: "Vulnérabilités" })).toBeVisible();
    const headers = (await screen.findAllByRole("columnheader")).map((h) => h.textContent);
    expect(headers).toEqual([
      "Identifiant",
      "Nom",
      "Ajout au catalogue KEV",
      "Usage par rançongiciel",
    ]);
  });

  it("shows each object with readable values and a link to its page", async () => {
    mockApi({ "/api/ontology": ontology, "/api/objects": page });

    renderApp("/objets/vulnerability");

    const row = (await screen.findByText("CVE-2024-10441")).closest("tr")!;
    expect(within(row).getByText("18 nov. 2026")).toBeVisible();
    expect(within(row).getByText("Avéré")).toBeVisible();
    expect(
      within(row).getByRole("link", { name: "Synology DSM Improper Encoding Vulnerability" }),
    ).toHaveAttribute("href", "/objets/vulnerability/CVE-2024-10441");
    expect(screen.getByText(/^2 résultats$/)).toBeVisible();
  });

  it("asks the API for the type's default sort", async () => {
    const calls = mockApi({ "/api/ontology": ontology, "/api/objects": page });

    renderApp("/objets/vulnerability");

    await screen.findByText("CVE-2024-10441");
    const request = calls.find((url) => url.pathname === "/api/objects")!;
    expect(request.searchParams.get("type")).toBe("vulnerability");
    expect(request.searchParams.get("sort")).toBe("kev_date_added");
    expect(request.searchParams.get("order")).toBe("desc");
  });

  it("searches when the form is submitted", async () => {
    const calls = mockApi({ "/api/ontology": ontology, "/api/objects": page });
    const user = userEvent.setup();
    renderApp("/objets/vulnerability");

    await user.type(await screen.findByRole("searchbox", { name: "Rechercher" }), "synology");
    await user.click(screen.getByRole("button", { name: "Rechercher" }));

    await waitFor(() =>
      expect(calls.some((url) => url.searchParams.get("q") === "synology")).toBe(true),
    );
  });

  it("offers a filter for each enum property", async () => {
    const calls = mockApi({ "/api/ontology": ontology, "/api/objects": page });
    const user = userEvent.setup();
    renderApp("/objets/vulnerability");

    await user.selectOptions(
      await screen.findByRole("combobox", { name: "Usage par rançongiciel" }),
      "Avéré",
    );

    await waitFor(() =>
      expect(
        calls.some((url) => url.searchParams.get("filter") === "ransomware_use:known"),
      ).toBe(true),
    );
  });

  it("says so when nothing matches", async () => {
    mockApi({
      "/api/ontology": ontology,
      "/api/objects": { items: [], total: 0, page: 1, size: 50 },
    });

    renderApp("/objets/vulnerability?q=zzz");

    expect(await screen.findByText(/Aucun résultat pour « zzz »/)).toBeVisible();
  });

  it("explains that an unknown type does not exist", async () => {
    mockApi({ "/api/ontology": ontology });

    renderApp("/objets/spaceship");

    expect(await screen.findByText(/n'existe pas dans l'ontologie/)).toBeVisible();
  });

  it("reports an API failure with a way to retry", async () => {
    mockApi({ "/api/ontology": ontology });

    renderApp("/objets/vulnerability");

    expect(await screen.findByRole("alert")).toHaveTextContent(/L'API n'a pas répondu/);
    expect(screen.getByRole("button", { name: "Réessayer" })).toBeVisible();
  });
});
