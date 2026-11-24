import { Link } from "react-router";

import { useOntology, useSources, useStats } from "../api/client";
import { Failure, Loading } from "../components/States";
import { formatCount, formatDateTime, plural } from "../lib/format";

export function Home() {
  const ontology = useOntology();
  const stats = useStats();
  const sources = useSources();

  if (ontology.isPending) return <Loading what="de l'ontologie" />;
  if (ontology.isError) return <Failure error={ontology.error} onRetry={ontology.refetch} />;

  const layers = Object.entries(ontology.data.layers);
  const types = Object.entries(ontology.data.object_types);
  const lastRun = sources.data
    ?.map((source) => source.last_run?.finished_at)
    .filter((date): date is string => Boolean(date))
    .sort()
    .at(-1);

  return (
    <div className="home">
      <div className="home__intro">
        <h1>Là où Internet touche terre.</h1>
        <p className="lead">
          Estran range des données ouvertes dans un seul monde d'objets reliés entre eux. Chaque
          information garde la trace de sa source et de sa licence.
        </p>
      </div>

      <div className="strata">
        {layers.map(([layerId, layer]) => {
          const layerTypes = types.filter(([, type]) => type.layer === layerId);
          const uncovered = layerTypes.length > 0;
          return (
            <section
              key={layerId}
              className={`stratum ${uncovered ? "stratum--uncovered" : "stratum--submerged"}`}
              aria-labelledby={`layer-${layerId}`}
            >
              <h2 id={`layer-${layerId}`}>{layer.label}</h2>
              {uncovered ? (
                <ul className="stratum__types">
                  {layerTypes.map(([typeId, type]) => (
                    <li key={typeId}>
                      <Link to={`/objets/${typeId}`}>
                        <span className="stratum__count">
                          {stats.data ? formatCount(stats.data.objects[typeId] ?? 0) : "…"}
                        </span>{" "}
                        <span>{type.plural}</span>
                      </Link>
                      <p>{type.description}</p>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="stratum__empty">
                  Encore sous l'eau : cette couche sera découverte dans une prochaine phase.
                </p>
              )}
            </section>
          );
        })}
      </div>

      {sources.data && (
        <p className="home__sources">
          {plural(sources.data.length, "source branchée", "sources branchées")}
          {lastRun ? `, dernier relevé le ${formatDateTime(lastRun)}. ` : ". "}
          <Link to="/sources">Voir l'état des sources</Link>
        </p>
      )}
    </div>
  );
}
