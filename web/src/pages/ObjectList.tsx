import type { FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router";

import { objectPath, useObjects, useOntology } from "../api/client";
import type { ObjectType } from "../api/types";
import { PropertyValue } from "../components/PropertyValue";
import { Failure, Loading, Notice } from "../components/States";
import { plural } from "../lib/format";

export function ObjectList() {
  const { type = "" } = useParams();
  const ontology = useOntology();

  if (ontology.isPending) return <Loading what="de l'ontologie" />;
  if (ontology.isError) return <Failure error={ontology.error} onRetry={ontology.refetch} />;

  const objectType = ontology.data.object_types[type];
  if (!objectType) {
    return (
      <Notice>
        Le type « {type} » n'existe pas dans l'ontologie. <Link to="/">Retour à l'accueil</Link>
      </Notice>
    );
  }
  // `key` remet la liste à zéro quand on change de type d'objet.
  return <TypedList key={type} type={type} objectType={objectType} />;
}

function TypedList({ type, objectType }: { type: string; objectType: ObjectType }) {
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const sort = params.get("sort") ?? objectType.default_sort.by;
  const order = params.get("order") === "asc" || params.get("order") === "desc"
    ? (params.get("order") as "asc" | "desc")
    : objectType.default_sort.order;
  const page = Math.max(1, Number(params.get("page")) || 1);
  const filters = params.getAll("filter");

  const objects = useObjects({ type, q, sort, order, page, filters }, true);

  const update = (change: (next: URLSearchParams) => void) => {
    const next = new URLSearchParams(params);
    next.delete("page");
    change(next);
    setParams(next);
  };

  const search = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const value = String(new FormData(event.currentTarget).get("q") ?? "").trim();
    update((next) => (value ? next.set("q", value) : next.delete("q")));
  };

  const setFilter = (property: string, value: string) =>
    update((next) => {
      const kept = next.getAll("filter").filter((f) => !f.startsWith(`${property}:`));
      next.delete("filter");
      for (const filter of kept) next.append("filter", filter);
      if (value) next.append("filter", `${property}:${value}`);
    });

  const sortBy = (column: string) =>
    update((next) => {
      next.set("sort", column);
      next.set("order", sort === column && order === "asc" ? "desc" : "asc");
    });

  const columns = [
    { id: "key", label: "Identifiant" },
    { id: "title", label: "Nom" },
    ...objectType.columns.map((id) => ({ id, label: objectType.properties[id]?.label ?? id })),
  ];
  const enums = Object.entries(objectType.properties).filter(([, p]) => p.type === "enum");
  const total = objects.data?.total ?? 0;
  const pages = objects.data ? Math.max(1, Math.ceil(total / objects.data.size)) : 1;

  return (
    <div className="page">
      <h1>{objectType.plural}</h1>
      {objectType.description && <p className="lead">{objectType.description}</p>}

      <div className="toolbar">
        <form role="search" onSubmit={search} key={q}>
          <input
            type="search"
            name="q"
            aria-label="Rechercher"
            placeholder="Identifiant, nom, description…"
            defaultValue={q}
          />
          <button type="submit" className="button">
            Rechercher
          </button>
        </form>
        {enums.map(([id, property]) => (
          <label key={id} className="filter">
            <span>{property.label}</span>
            <select
              value={filters.find((f) => f.startsWith(`${id}:`))?.slice(id.length + 1) ?? ""}
              onChange={(event) => setFilter(id, event.target.value)}
            >
              <option value="">Tous</option>
              {Object.entries(property.values ?? {}).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        ))}
      </div>

      {objects.isPending && <Loading what="des objets" />}
      {objects.isError && <Failure error={objects.error} onRetry={objects.refetch} />}
      {objects.data && total === 0 && (
        <Notice>
          {q
            ? `Aucun résultat pour « ${q} ». Essayez un autre mot ou retirez les filtres.`
            : "Aucun objet de ce type pour l'instant. La première collecte est peut-être en cours."}
        </Notice>
      )}
      {objects.data && total > 0 && (
        <>
          <p className="result-count">{plural(total, "résultat", "résultats")}</p>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  {columns.map((column) => (
                    <th
                      key={column.id}
                      scope="col"
                      aria-sort={
                        sort !== column.id ? "none" : order === "asc" ? "ascending" : "descending"
                      }
                    >
                      <button type="button" onClick={() => sortBy(column.id)}>
                        {column.label}
                      </button>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {objects.data.items.map((item) => (
                  <tr key={item.key}>
                    <td className="identifier">{item.key}</td>
                    <td>
                      <Link to={objectPath(item.type, item.key)}>{item.title}</Link>
                    </td>
                    {objectType.columns.map((id) => {
                      const property = objectType.properties[id];
                      return (
                        <td key={id}>
                          {property && item.properties[id] !== undefined && (
                            <PropertyValue property={property} value={item.properties[id]} />
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {pages > 1 && (
            <nav className="pagination" aria-label="Pages de résultats">
              <button
                type="button"
                className="button"
                disabled={page <= 1}
                onClick={() => setParams(withPage(params, page - 1))}
              >
                Page précédente
              </button>
              <span>
                Page {page} sur {pages}
              </span>
              <button
                type="button"
                className="button"
                disabled={page >= pages}
                onClick={() => setParams(withPage(params, page + 1))}
              >
                Page suivante
              </button>
            </nav>
          )}
        </>
      )}
    </div>
  );
}

function withPage(params: URLSearchParams, page: number): URLSearchParams {
  const next = new URLSearchParams(params);
  next.set("page", String(page));
  return next;
}
