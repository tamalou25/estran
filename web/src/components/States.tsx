import type { ReactNode } from "react";

import { ApiError } from "../api/client";

export function Loading({ what }: { what: string }) {
  return (
    <p className="state" role="status">
      Chargement {what}…
    </p>
  );
}

export function Failure({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const detail =
    error instanceof ApiError
      ? `L'API n'a pas répondu correctement (erreur ${error.status}).`
      : "L'API n'a pas répondu. Vérifiez que les conteneurs tournent : docker compose ps.";
  return (
    <div className="state state--error" role="alert">
      <p>{detail}</p>
      <button type="button" className="button" onClick={onRetry}>
        Réessayer
      </button>
    </div>
  );
}

export function Notice({ children }: { children: ReactNode }) {
  return <p className="state">{children}</p>;
}
