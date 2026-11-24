import type { ObjectType, Provenance } from "../api/types";
import { formatDateTime } from "../lib/format";

/**
 * Note de marge, comme sur une carte marine : d'où vient l'information, sous quelle
 * licence, et quand elle a été relevée pour la dernière fois.
 */
export function ProvenanceNote({
  provenance,
  objectType,
}: {
  provenance: Provenance[];
  objectType: ObjectType;
}) {
  return (
    <aside className="marginalia" aria-labelledby="provenance-title">
      <h2 id="provenance-title">Provenance</h2>
      {provenance.length === 0 && <p>Aucune source enregistrée pour cet objet.</p>}
      {provenance.map(({ source, fields, last_seen }) => (
        <dl key={source.id}>
          <dt>Source</dt>
          <dd>
            <a href={source.homepage} rel="noreferrer noopener" target="_blank">
              {source.name}
            </a>
          </dd>
          <dt>Publiée par</dt>
          <dd>{source.attribution}</dd>
          <dt>Licence</dt>
          <dd>
            <a href={source.licence_url} rel="noreferrer noopener" target="_blank">
              {source.licence}
            </a>
          </dd>
          <dt>Dernier relevé</dt>
          <dd>{formatDateTime(last_seen)}</dd>
          {fields.length > 0 && (
            <>
              <dt>Champs fournis</dt>
              <dd>
                {fields.map((field) => objectType.properties[field]?.label ?? field).join(", ")}
              </dd>
            </>
          )}
        </dl>
      ))}
    </aside>
  );
}
