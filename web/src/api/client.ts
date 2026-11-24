import { keepPreviousData, useQuery } from "@tanstack/react-query";

import type {
  Neighbors,
  ObjectDetail,
  ObjectPage,
  Ontology,
  SourceStatus,
  Stats,
} from "./types";

export class ApiError extends Error {
  constructor(readonly status: number) {
    super(`API answered ${status}`);
  }
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new ApiError(response.status);
  return (await response.json()) as T;
}

export function objectPath(type: string, key: string): string {
  return `/objets/${encodeURIComponent(type)}/${encodeURIComponent(key)}`;
}

function objectApiPath(type: string, key: string): string {
  return `/api/objects/${encodeURIComponent(type)}/${encodeURIComponent(key)}`;
}

export function isNotFound(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

export function useOntology() {
  return useQuery({
    queryKey: ["ontology"],
    queryFn: () => getJson<Ontology>("/api/ontology"),
    staleTime: Infinity,
  });
}

export interface ObjectQuery {
  type: string;
  q: string;
  sort: string;
  order: "asc" | "desc";
  page: number;
  filters: string[];
}

export function useObjects(query: ObjectQuery, enabled: boolean) {
  const params = new URLSearchParams({
    type: query.type,
    sort: query.sort,
    order: query.order,
    page: String(query.page),
  });
  if (query.q) params.set("q", query.q);
  for (const filter of query.filters) params.append("filter", filter);
  const search = params.toString();
  return useQuery({
    queryKey: ["objects", search],
    queryFn: () => getJson<ObjectPage>(`/api/objects?${search}`),
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useObject(type: string, key: string) {
  return useQuery({
    queryKey: ["object", type, key],
    queryFn: () => getJson<ObjectDetail>(objectApiPath(type, key)),
  });
}

export function useNeighbors(type: string, key: string) {
  return useQuery({
    queryKey: ["neighbors", type, key],
    queryFn: () => getJson<Neighbors>(`${objectApiPath(type, key)}/neighbors?limit=200`),
  });
}

/** Voisins d'un objet, hors du cache : l'explorateur de graphe les demande à la volée. */
export function fetchNeighbors(type: string, key: string, limit: number): Promise<Neighbors> {
  return getJson<Neighbors>(`${objectApiPath(type, key)}/neighbors?limit=${limit}`);
}

export function useStats() {
  return useQuery({ queryKey: ["stats"], queryFn: () => getJson<Stats>("/api/stats") });
}

export function useSources() {
  return useQuery({
    queryKey: ["sources"],
    queryFn: () => getJson<SourceStatus[]>("/api/sources"),
  });
}
