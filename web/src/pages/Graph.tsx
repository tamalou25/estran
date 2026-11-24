import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { Link, useParams } from "react-router";

import { fetchNeighbors, isNotFound, objectPath, useObject, useOntology } from "../api/client";
import type { Ontology } from "../api/types";
import { Failure, Loading, Notice } from "../components/States";

/** Voisins ajoutés par ouverture d'un nœud : au-delà, le dessin devient illisible. */
const NEIGHBOURS_PER_NODE = 30;
const NODE_RADIUS = 13;

interface GraphNode {
  id: string;
  type: string;
  key: string;
  title: string;
  /** Renseignés une fois le nœud ouvert. */
  shown?: number;
  total?: number;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  nature: "fact" | "hypothesis";
}

type Point = { x: number; y: number };

const nodeId = (type: string, key: string) => `${type}/${key}`;

export function graphPath(type: string, key: string): string {
  return `/graphe/${encodeURIComponent(type)}/${encodeURIComponent(key)}`;
}

export function Graph() {
  const { type = "", key = "" } = useParams();
  const ontology = useOntology();
  const start = useObject(type, key);

  if (ontology.isPending || start.isPending) return <Loading what="du graphe" />;
  if (ontology.isError) return <Failure error={ontology.error} onRetry={ontology.refetch} />;
  if (start.isError) {
    return isNotFound(start.error) ? (
      <Notice>
        Cet objet n'existe pas, ou n'a pas encore été collecté. <Link to="/">Retour à l'accueil</Link>
      </Notice>
    ) : (
      <Failure error={start.error} onRetry={start.refetch} />
    );
  }
  // `key` repart d'un graphe vide quand on recentre sur un autre objet.
  return (
    <Explorer
      key={nodeId(type, key)}
      ontology={ontology.data}
      start={{ id: nodeId(type, key), type, key, title: start.data.title }}
    />
  );
}

function Explorer({ ontology, start }: { ontology: Ontology; start: GraphNode }) {
  const [nodes, setNodes] = useState<Map<string, GraphNode>>(() => new Map([[start.id, start]]));
  const [edges, setEdges] = useState<Map<string, GraphEdge>>(() => new Map());
  const [selected, setSelected] = useState(start.id);
  const [failed, setFailed] = useState<unknown>(null);
  const opening = useRef(new Set<string>());

  const open = useCallback(async (node: GraphNode) => {
    if (opening.current.has(node.id)) return; // déjà ouvert ou en cours
    opening.current.add(node.id);
    try {
      const { items, total } = await fetchNeighbors(node.type, node.key, NEIGHBOURS_PER_NODE);
      setNodes((current) => {
        const next = new Map(current);
        for (const { object } of items) {
          const id = nodeId(object.type, object.key);
          if (!next.has(id)) next.set(id, { id, ...object });
        }
        next.set(node.id, { ...(next.get(node.id) ?? node), shown: items.length, total });
        return next;
      });
      setEdges((current) => {
        const next = new Map(current);
        for (const item of items) {
          const other = nodeId(item.object.type, item.object.key);
          const [source, target] = item.direction === "out" ? [node.id, other] : [other, node.id];
          const id = `${item.link_type}:${source}->${target}`;
          next.set(id, { id, source, target, nature: item.nature });
        }
        return next;
      });
      setFailed(null);
    } catch (error) {
      opening.current.delete(node.id);
      setFailed(error);
    }
  }, []);

  useEffect(() => {
    void open(start);
  }, [open, start]);

  const positions = useLayout(nodes, edges);
  const frame = useMemo(() => viewBox(positions), [positions]);
  const current = nodes.get(selected) ?? start;
  const typeLabel = (type: string) => ontology.object_types[type]?.label ?? type;
  const presentTypes = [...new Set([...nodes.values()].map((node) => node.type))];

  const activate = (node: GraphNode) => {
    setSelected(node.id);
    void open(node);
  };
  const onKey = (event: KeyboardEvent, node: GraphNode) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      activate(node);
    }
  };

  return (
    <div className="page">
      <p className="sheet__kind">
        <Link to={objectPath(start.type, start.key)}>{typeLabel(start.type)}</Link>
        <span className="identifier">{start.key}</span>
      </p>
      <h1>{start.title}</h1>
      <p className="lead">
        Chaque rond est un objet, chaque trait un lien. Ouvrez un objet pour faire apparaître ses
        voisins.
      </p>
      {failed !== null && <Failure error={failed} onRetry={() => void open(current)} />}

      <div className="graph">
        <svg
          className="graph__canvas"
          viewBox={frame}
          role="group"
          aria-label={`Graphe autour de ${start.title} : ${nodes.size} objets, ${edges.size} liens`}
        >
          {[...edges.values()].map((edge) => {
            const from = positions.get(edge.source);
            const to = positions.get(edge.target);
            if (!from || !to) return null;
            return (
              <line
                key={edge.id}
                className={`edge edge--${edge.nature}`}
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
              />
            );
          })}
          {[...nodes.values()].map((node) => {
            const at = positions.get(node.id);
            if (!at) return null;
            const state = node.id === selected ? " node--selected" : "";
            return (
              <g
                key={node.id}
                className={`node node--${node.type}${state}`}
                transform={`translate(${at.x} ${at.y})`}
                role="button"
                tabIndex={0}
                aria-label={`${node.title}, ${typeLabel(node.type)}`}
                aria-pressed={node.id === selected}
                onClick={() => activate(node)}
                onKeyDown={(event) => onKey(event, node)}
              >
                <circle r={NODE_RADIUS} />
                <text y={NODE_RADIUS + 14} aria-hidden="true">
                  {shorten(node.title)}
                </text>
              </g>
            );
          })}
        </svg>

        <aside className="marginalia" aria-labelledby="selected-title">
          <h2 id="selected-title">Objet sélectionné</h2>
          <dl>
            <dt>{typeLabel(current.type)}</dt>
            <dd>{current.title}</dd>
            <dt>Identifiant</dt>
            <dd>{current.key}</dd>
            {current.total !== undefined && (
              <>
                <dt>Voisins</dt>
                <dd>
                  {current.shown === current.total
                    ? `${current.total} affichés`
                    : `${current.shown} voisins affichés sur ${current.total}`}
                </dd>
              </>
            )}
          </dl>
          <p className="graph__actions">
            <Link to={objectPath(current.type, current.key)}>Ouvrir la fiche</Link>
            {current.id !== start.id && (
              <Link to={graphPath(current.type, current.key)}>Recentrer le graphe ici</Link>
            )}
          </p>
          <h2>Légende</h2>
          <ul className="legend">
            {presentTypes.map((type) => (
              <li key={type}>
                <span className={`legend__dot node--${type}`} aria-hidden="true" />
                {typeLabel(type)}
              </li>
            ))}
          </ul>
          <p>Trait continu : lien établi par une source.</p>
          <p>Trait interrompu : lien déduit par Estran, à vérifier.</p>
        </aside>
      </div>
    </div>
  );
}

/**
 * Disposition par forces, calculée d'un coup (pas d'animation) : les objets déjà placés
 * gardent leur position de départ, ce qui évite que le dessin saute à chaque ouverture.
 */
function useLayout(nodes: Map<string, GraphNode>, edges: Map<string, GraphEdge>) {
  const previous = useRef(new Map<string, Point>());
  return useMemo(() => {
    type Sim = SimulationNodeDatum & { id: string };
    const simNodes: Sim[] = [...nodes.keys()].map((id) => ({ id, ...previous.current.get(id) }));
    const simLinks: SimulationLinkDatum<Sim>[] = [...edges.values()].map((edge) => ({
      source: edge.source,
      target: edge.target,
    }));
    const simulation = forceSimulation(simNodes)
      .force(
        "link",
        forceLink<Sim, SimulationLinkDatum<Sim>>(simLinks)
          .id((node) => node.id)
          .distance(120),
      )
      .force("charge", forceManyBody().strength(-520))
      .force("collide", forceCollide(NODE_RADIUS * 3.6))
      .force("center", forceCenter(0, 0))
      .stop();
    for (let step = 0; step < 240; step += 1) simulation.tick();
    const positions = new Map(simNodes.map((n) => [n.id, { x: n.x ?? 0, y: n.y ?? 0 }]));
    previous.current = positions;
    return positions;
  }, [nodes, edges]);
}

function viewBox(positions: Map<string, Point>): string {
  const points = [...positions.values()];
  const xs = points.map((p) => p.x);
  const ys = points.map((p) => p.y);
  const margin = 90;
  const left = Math.min(0, ...xs) - margin;
  const top = Math.min(0, ...ys) - margin;
  const width = Math.max(0, ...xs) - left + margin;
  const height = Math.max(0, ...ys) - top + margin;
  return `${left} ${top} ${Math.max(width, 360)} ${Math.max(height, 300)}`;
}

function shorten(title: string, max = 28): string {
  return title.length <= max ? title : `${title.slice(0, max - 1).trimEnd()}…`;
}
