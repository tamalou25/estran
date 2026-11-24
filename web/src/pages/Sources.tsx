import { useSources } from "../api/client";
import type { Run } from "../api/types";
import { Failure, Loading, Notice } from "../components/States";
import { formatCount, formatDateTime } from "../lib/format";

const STATUS: Record<Run["status"], string> = {
  success: "Collecte réussie",
  unchanged: "Source inchangée",
  running: "Collecte en cours",
  failed: "Échec",
};

function LastRun({ run }: { run: Run | null }) {
  if (!run) return <>Jamais collectée</>;
  const when = formatDateTime(run.finished_at ?? run.started_at);
  const origin = run.mode === "live" ? "" : " (instantané embarqué)";
  return (
    <>
      <span className={`run run--${run.status}`}>
        {STATUS[run.status]} le {when}
        {origin}
      </span>
      {run.error && <span className="run__error">{run.error}</span>}
    </>
  );
}

export function Sources() {
  const sources = useSources();

  return (
    <div className="page">
      <h1>Sources et licences</h1>
      <p className="lead">
        Chaque source est collectée telle que son éditeur la publie. Seules les sources dont la
        licence le permet sont embarquées dans l'instantané de démonstration.
      </p>
      {sources.isPending && <Loading what="des sources" />}
      {sources.isError && <Failure error={sources.error} onRetry={sources.refetch} />}
      {sources.data?.length === 0 && (
        <Notice>
          Aucune source n'a encore été collectée. Le collecteur démarre peut-être : rechargez la
          page dans un instant.
        </Notice>
      )}
      {sources.data && sources.data.length > 0 && (
        <div className="table-scroll">
          <table className="table--wide">
            <thead>
              <tr>
                <th scope="col">Source</th>
                <th scope="col">Licence</th>
                <th scope="col">Redistribution</th>
                <th scope="col" className="numeric">
                  Objets
                </th>
                <th scope="col">Dernière collecte</th>
              </tr>
            </thead>
            <tbody>
              {sources.data.map((source) => (
                <tr key={source.id}>
                  <td>
                    <a href={source.homepage} rel="noreferrer noopener" target="_blank">
                      {source.name}
                    </a>
                    <span className="cell-note">{source.attribution}</span>
                  </td>
                  <td>
                    <a href={source.licence_url} rel="noreferrer noopener" target="_blank">
                      {source.licence}
                    </a>
                  </td>
                  <td>{source.redistributable ? "Autorisée" : "Interdite"}</td>
                  <td className="numeric">{formatCount(source.objects_count)}</td>
                  <td>
                    <LastRun run={source.last_run} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
