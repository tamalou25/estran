// Contrat de l'API en lecture seule (server/estran/api/schemas.py en est le pendant).

export type PropertyKind =
  | "text"
  | "integer"
  | "number"
  | "boolean"
  | "date"
  | "datetime"
  | "url"
  | "enum"
  | "text_list";

export interface PropertyType {
  label: string;
  type: PropertyKind;
  required: boolean;
  searchable: boolean;
  values: Record<string, string> | null;
  unit?: "percent" | null;
}

export interface ObjectType {
  label: string;
  plural: string;
  layer: string;
  description: string;
  columns: string[];
  default_sort: { by: string; order: "asc" | "desc" };
  properties: Record<string, PropertyType>;
}

export interface LinkType {
  label: string;
  inverse_label: string;
  from: string;
  to: string;
}

export interface Ontology {
  version: number;
  layers: Record<string, { label: string }>;
  object_types: Record<string, ObjectType>;
  link_types: Record<string, LinkType>;
}

export type Properties = Record<string, unknown>;

export interface ObjectSummary {
  type: string;
  key: string;
  title: string;
  properties: Properties;
  first_seen: string;
  last_seen: string;
}

export interface ObjectPage {
  items: ObjectSummary[];
  total: number;
  page: number;
  size: number;
}

export interface SourceInfo {
  id: string;
  name: string;
  homepage: string;
  licence: string;
  licence_url: string;
  attribution: string;
  redistributable: boolean;
}

export interface Run {
  id: number;
  source_id: string;
  mode: string;
  status: "running" | "success" | "unchanged" | "failed";
  started_at: string;
  finished_at: string | null;
  objects_count: number;
  links_count: number;
  skipped_count: number;
  error: string | null;
}

export interface Provenance {
  source: SourceInfo;
  fields: string[];
  first_seen: string;
  last_seen: string;
}

export interface ObjectDetail extends ObjectSummary {
  provenance: Provenance[];
}

export interface Neighbor {
  link_type: string;
  direction: "out" | "in";
  nature: "fact" | "hypothesis";
  object: { type: string; key: string; title: string };
}

export interface Neighbors {
  items: Neighbor[];
  total: number;
}

export interface Stats {
  objects: Record<string, number>;
  links: number;
}

export interface SourceStatus extends SourceInfo {
  objects_count: number;
  last_run: Run | null;
}
