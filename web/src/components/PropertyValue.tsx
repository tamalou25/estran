import type { PropertyType } from "../api/types";
import { displayValue } from "../lib/format";

function hostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function isWebUrl(value: string): boolean {
  return value.startsWith("https://") || value.startsWith("http://");
}

/** Affiche une valeur selon son type d'ontologie. Rien n'est jamais interprété comme du HTML. */
export function PropertyValue({ property, value }: { property: PropertyType; value: unknown }) {
  if (property.type === "url" && typeof value === "string" && isWebUrl(value)) {
    return (
      <a href={value} rel="noreferrer noopener" target="_blank">
        {hostname(value)}
      </a>
    );
  }
  if (property.type === "enum") {
    return <span className={`tag tag--${String(value)}`}>{displayValue(property, value)}</span>;
  }
  return <>{displayValue(property, value)}</>;
}
