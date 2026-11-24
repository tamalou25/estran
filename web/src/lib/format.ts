import type { PropertyType } from "../api/types";

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

const dayFormat = new Intl.DateTimeFormat("fr-FR", {
  day: "numeric",
  month: "short",
  year: "numeric",
  timeZone: "UTC",
});

const countFormat = new Intl.NumberFormat("fr-FR");

/** Date de calendrier (AAAA-MM-JJ) : affichée telle quelle, sans décalage de fuseau. */
export function formatDate(value: string): string {
  if (!DATE_ONLY.test(value)) return value;
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? value : dayFormat.format(date);
}

/** Instant précis : affiché dans le fuseau de l'utilisateur (ou celui demandé). */
export function formatDateTime(value: string, timeZone?: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const day = new Intl.DateTimeFormat("fr-FR", {
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone,
  }).format(date);
  const time = new Intl.DateTimeFormat("fr-FR", {
    hour: "2-digit",
    minute: "2-digit",
    timeZone,
  }).format(date);
  return `${day} à ${time}`;
}

export function formatCount(value: number): string {
  return countFormat.format(value);
}

/** Texte lisible d'une valeur, selon le type déclaré dans l'ontologie. */
export function displayValue(property: PropertyType, value: unknown): string {
  if (value === undefined || value === null) return "";
  switch (property.type) {
    case "date":
      return formatDate(String(value));
    case "datetime":
      return formatDateTime(String(value));
    case "enum":
      return property.values?.[String(value)] ?? String(value);
    case "boolean":
      return value ? "Oui" : "Non";
    case "integer":
    case "number":
      return typeof value === "number" ? countFormat.format(value) : String(value);
    case "text_list":
      return Array.isArray(value) ? value.join(", ") : String(value);
    default:
      return String(value);
  }
}

export function plural(count: number, one: string, many: string): string {
  return `${formatCount(count)} ${count > 1 ? many : one}`;
}
