import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { vi } from "vitest";

import { AppRoutes } from "../App";
import type { Ontology } from "../api/types";

export const ontology: Ontology = {
  version: 1,
  layers: {
    territoire: { label: "Territoire" },
    infrastructure: { label: "Infrastructure" },
    menace: { label: "Menace" },
  },
  object_types: {
    vulnerability: {
      label: "Vulnérabilité",
      plural: "Vulnérabilités",
      layer: "menace",
      description: "Faille de sécurité référencée par un identifiant CVE.",
      columns: ["kev_date_added", "ransomware_use"],
      default_sort: { by: "kev_date_added", order: "desc" },
      properties: {
        name: { label: "Nom", type: "text", required: true, searchable: true, values: null },
        description: {
          label: "Description",
          type: "text",
          required: false,
          searchable: true,
          values: null,
        },
        kev_date_added: {
          label: "Ajout au catalogue KEV",
          type: "date",
          required: false,
          searchable: false,
          values: null,
        },
        ransomware_use: {
          label: "Usage par rançongiciel",
          type: "enum",
          required: false,
          searchable: false,
          values: { known: "Avéré", unknown: "Non connu" },
        },
        cwes: {
          label: "Faiblesses (CWE)",
          type: "text_list",
          required: false,
          searchable: false,
          values: null,
        },
        cve_url: {
          label: "Fiche CVE",
          type: "url",
          required: false,
          searchable: false,
          values: null,
        },
      },
    },
    product: {
      label: "Produit",
      plural: "Produits",
      layer: "menace",
      description: "Logiciel ou matériel touché par des vulnérabilités.",
      columns: [],
      default_sort: { by: "title", order: "asc" },
      properties: {
        name: { label: "Nom", type: "text", required: true, searchable: true, values: null },
      },
    },
  },
  link_types: {
    affects: {
      label: "affecte",
      inverse_label: "est affecté par",
      from: "vulnerability",
      to: "product",
    },
  },
};

type Answer = unknown | ((url: URL) => unknown);

/**
 * Remplace `fetch` : chaque chemin d'API reçoit la réponse donnée. Un chemin non prévu
 * répond 404, comme le ferait l'API. Renvoie la liste des URL appelées.
 */
export function mockApi(answers: Record<string, Answer>): URL[] {
  const calls: URL[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), "http://estran.test");
      calls.push(url);
      const answer = answers[url.pathname];
      if (answer === undefined) {
        return new Response(JSON.stringify({ detail: "Not found" }), { status: 404 });
      }
      const body = typeof answer === "function" ? (answer as (u: URL) => unknown)(url) : answer;
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  return calls;
}

export function renderApp(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
