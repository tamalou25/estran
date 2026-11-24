import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { Neighbors, ObjectDetail } from "../api/types";
import { mockApi, ontology, renderApp } from "../test/helpers";

const object = (type: string, key: string, title: string): ObjectDetail => ({
  type,
  key,
  title,
  properties: { name: title },
  first_seen: "2026-11-24T10:00:00+00:00",
  last_seen: "2026-11-24T10:00:00+00:00",
  provenance: [],
});

const cveNeighbors: Neighbors = {
  total: 1,
  items: [
    {
      link_type: "affects",
      direction: "out",
      nature: "fact",
      object: { type: "product", key: "adobe:commerce", title: "Commerce" },
    },
  ],
};

const productNeighbors: Neighbors = {
  total: 45,
  items: [
    {
      link_type: "affects",
      direction: "in",
      nature: "fact",
      object: { type: "vulnerability", key: "CVE-2024-34102", title: "Adobe Commerce XXE" },
    },
    {
      link_type: "affects",
      direction: "in",
      nature: "hypothesis",
      object: { type: "vulnerability", key: "CVE-2022-24086", title: "Adobe Commerce Input" },
    },
  ],
};

const api = {
  "/api/ontology": ontology,
  "/api/objects/vulnerability/CVE-2024-34102": object(
    "vulnerability",
    "CVE-2024-34102",
    "Adobe Commerce XXE",
  ),
  "/api/objects/vulnerability/CVE-2024-34102/neighbors": cveNeighbors,
  "/api/objects/product/adobe%3Acommerce/neighbors": productNeighbors,
};

const node = (name: RegExp) => screen.findByRole("button", { name });

describe("graph explorer", () => {
  it("draws the starting object and its neighbours", async () => {
    mockApi(api);

    renderApp("/graphe/vulnerability/CVE-2024-34102");

    expect(await node(/Adobe Commerce XXE, Vulnérabilité/)).toBeVisible();
    expect(await node(/Commerce, Produit/)).toBeVisible();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Adobe Commerce XXE");
  });

  it("grows when a neighbour is opened, without duplicating what is already drawn", async () => {
    mockApi(api);
    const user = userEvent.setup();
    renderApp("/graphe/vulnerability/CVE-2024-34102");

    await user.click(await node(/Commerce, Produit/));

    expect(await node(/Adobe Commerce Input, Vulnérabilité/)).toBeVisible();
    expect(screen.getAllByRole("button", { name: /Adobe Commerce XXE, Vulnérabilité/ })).toHaveLength(1);
  });

  it("says how many neighbours it leaves out, and where to see them all", async () => {
    mockApi(api);
    const user = userEvent.setup();
    renderApp("/graphe/vulnerability/CVE-2024-34102");

    await user.click(await node(/Commerce, Produit/));

    const panel = await screen.findByRole("complementary", { name: "Objet sélectionné" });
    await waitFor(() => expect(panel).toHaveTextContent(/2 voisins affichés sur 45/));
    expect(within(panel).getByRole("link", { name: /Ouvrir la fiche/ })).toHaveAttribute(
      "href",
      "/objets/product/adobe%3Acommerce",
    );
  });

  it("can be driven from the keyboard", async () => {
    mockApi(api);
    const user = userEvent.setup();
    renderApp("/graphe/vulnerability/CVE-2024-34102");

    (await node(/Commerce, Produit/)).focus();
    await user.keyboard("{Enter}");

    expect(await node(/Adobe Commerce Input, Vulnérabilité/)).toBeVisible();
  });

  it("marks a deduced link differently from a stated one", async () => {
    mockApi(api);
    const user = userEvent.setup();
    const { container } = renderApp("/graphe/vulnerability/CVE-2024-34102");

    await user.click(await node(/Commerce, Produit/));
    await node(/Adobe Commerce Input, Vulnérabilité/);

    expect(container.querySelectorAll("line.edge--hypothesis")).toHaveLength(1);
    expect(container.querySelectorAll("line.edge--fact")).toHaveLength(1);
    expect(screen.getByText(/Trait interrompu : lien déduit/)).toBeVisible();
  });

  it("is reachable from an object page", async () => {
    mockApi(api);

    renderApp("/objets/vulnerability/CVE-2024-34102");

    expect(await screen.findByRole("link", { name: "Explorer le graphe" })).toHaveAttribute(
      "href",
      "/graphe/vulnerability/CVE-2024-34102",
    );
  });

  it("explains an unknown starting object", async () => {
    mockApi({ "/api/ontology": ontology });

    renderApp("/graphe/vulnerability/CVE-1999-0000");

    expect(await screen.findByText(/Cet objet n'existe pas/)).toBeVisible();
  });
});
