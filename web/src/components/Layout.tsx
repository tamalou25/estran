import type { ReactNode } from "react";
import { Link, NavLink } from "react-router";

import { useOntology } from "../api/client";

export function Layout({ children }: { children: ReactNode }) {
  const ontology = useOntology();
  const types = Object.entries(ontology.data?.object_types ?? {});

  return (
    <>
      <a className="skip-link" href="#contenu">
        Aller au contenu
      </a>
      <header className="masthead">
        <Link className="wordmark" to="/">
          <svg aria-hidden="true" viewBox="0 0 44 16" width="44" height="16">
            <path
              d="M1 9c3.5-7 7-7 10.5 0s7 7 10.5 0 7-7 10.5 0 5.5 5.5 10.5 1"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.2"
              strokeLinecap="round"
            />
          </svg>
          Estran
        </Link>
        <nav aria-label="Navigation principale">
          <ul>
            {types.map(([id, type]) => (
              <li key={id}>
                <NavLink to={`/objets/${id}`}>{type.plural}</NavLink>
              </li>
            ))}
            <li>
              <NavLink to="/sources">Sources</NavLink>
            </li>
          </ul>
        </nav>
      </header>
      <main id="contenu">{children}</main>
      <footer className="colophon">
        <p>
          Estran ne contient que des données ouvertes, chacune sous sa licence :{" "}
          <Link to="/sources">sources et licences</Link>. Aucune donnée personnelle n'est
          collectée.
        </p>
      </footer>
    </>
  );
}
