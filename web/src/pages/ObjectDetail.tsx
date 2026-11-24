import { Link, useParams } from "react-router";

import { isNotFound, objectPath, useNeighbors, useObject, useOntology } from "../api/client";
import type { Neighbor, Ontology } from "../api/types";
import { PropertyValue } from "../components/PropertyValue";
import { ProvenanceNote } from "../components/ProvenanceNote";
import { graphPath } from "./Graph";
import { Failure, Loading, Notice } from "../components/States";
import { formatDateTime } from "../lib/format";

// Affichés dans l'en-tête de la fiche, donc pas répétés dans la liste des propriétés.
const HEADER_PROPERTIES = new Set(["name", "description"]);

export function ObjectDetail() {
  const { type = "", key = "" } = useParams();
  const ontology = useOntology();
  const object = useObject(type, key);
  const neighbors = useNeighbors(type, key);

  if (ontology.isPending || object.isPending) return <Loading what="de la fiche" />;
  if (ontology.isError) return <Failure error={ontology.error} onRetry={ontology.refetch} />;
  if (object.isError) {
    return isNotFound(object.error) ? (
      <Notice>
        Cet objet n'existe pas, ou n'a pas encore été collecté. <Link to="/">Retour à l'accueil</Link>
      </Notice>
    ) : (
      <Failure error={object.error} onRetry={object.refetch} />
    );
  }

  const objectType = ontology.data.object_types[type];
  if (!objectType) return <Notice>Le type « {type} » n'existe pas dans l'ontologie.</Notice>;

  const item = object.data;
  const description = item.properties.description;
  const properties = Object.entries(objectType.properties).filter(
    ([id]) => !HEADER_PROPERTIES.has(id) && item.properties[id] !== undefined,
  );

  return (
    <div className="sheet">
      <article className="sheet__main">
        <header>
          <p className="sheet__kind">
            <Link to={`/objets/${type}`}>{objectType.label}</Link>
            <span className="identifier">{item.key}</span>
          </p>
          <h1>{item.title}</h1>
          {typeof description === "string" && <p className="lead">{description}</p>}
        </header>

        {properties.length > 0 && (
          <section aria-labelledby="properties-title">
            <h2 id="properties-title">Propriétés</h2>
            <dl className="properties">
              {properties.map(([id, property]) => (
                <div key={id}>
                  <dt>{property.label}</dt>
                  <dd>
                    <PropertyValue property={property} value={item.properties[id]} />
                  </dd>
                </div>
              ))}
            </dl>
          </section>
        )}

        <section aria-labelledby="links-title">
          <h2 id="links-title">Liens</h2>
          {neighbors.isPending && <Loading what="des liens" />}
          {neighbors.isError && <Failure error={neighbors.error} onRetry={neighbors.refetch} />}
          {neighbors.data && neighbors.data.items.length === 0 && (
            <p>Cet objet n'est relié à aucun autre pour l'instant.</p>
          )}
          {neighbors.data && neighbors.data.items.length > 0 && (
            <>
              <p className="sheet__graph">
                <Link to={graphPath(type, key)}>Explorer le graphe</Link>
              </p>
              <ul className="relations">
                {groupByRelation(neighbors.data.items, ontology.data).map((group) => (
                  <li key={group.label}>
                    <h3 className="relation">
                      <span className="relation__label">{group.label}</span>
                      <span className="relation__count">{group.items.length}</span>
                    </h3>
                    <ul className="cables">
                      {group.items.map((neighbor) => (
                        <NeighborItem
                          key={`${neighbor.link_type}-${neighbor.direction}-${neighbor.object.type}-${neighbor.object.key}`}
                          neighbor={neighbor}
                          ontology={ontology.data}
                        />
                      ))}
                    </ul>
                  </li>
                ))}
              </ul>
              {neighbors.data.total > neighbors.data.items.length && (
                <p className="cell-note">
                  {neighbors.data.items.length} liens affichés sur {neighbors.data.total}.
                </p>
              )}
            </>
          )}
        </section>

        <p className="sheet__seen">Dans Estran depuis le {formatDateTime(item.first_seen)}.</p>
      </article>

      <ProvenanceNote provenance={item.provenance} objectType={objectType} />
    </div>
  );
}

function relationLabel(neighbor: Neighbor, ontology: Ontology): string {
  const linkType = ontology.link_types[neighbor.link_type];
  return neighbor.direction === "out"
    ? (linkType?.label ?? neighbor.link_type)
    : (linkType?.inverse_label ?? neighbor.link_type);
}

/** « affecte », « est mentionnée par »… : un groupe par relation, dans l'ordre de l'API. */
function groupByRelation(items: Neighbor[], ontology: Ontology) {
  const groups = new Map<string, Neighbor[]>();
  for (const item of items) {
    const label = relationLabel(item, ontology);
    groups.set(label, [...(groups.get(label) ?? []), item]);
  }
  return [...groups].map(([label, grouped]) => ({ label, items: grouped }));
}

function NeighborItem({ neighbor, ontology }: { neighbor: Neighbor; ontology: Ontology }) {
  const targetType = ontology.object_types[neighbor.object.type];

  return (
    <li className={neighbor.nature === "hypothesis" ? "cable cable--hypothesis" : "cable"}>
      <span className="cable__relation" aria-hidden="true" />
      <span className="cable__target">
        <Link to={objectPath(neighbor.object.type, neighbor.object.key)}>
          {neighbor.object.title}
        </Link>
        <span className="cell-note">{targetType?.label ?? neighbor.object.type}</span>
      </span>
    </li>
  );
}
