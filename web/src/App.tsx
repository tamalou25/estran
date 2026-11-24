import { Link, Route, Routes } from "react-router";

import { Layout } from "./components/Layout";
import { Notice } from "./components/States";
import { Graph } from "./pages/Graph";
import { Home } from "./pages/Home";
import { ObjectDetail } from "./pages/ObjectDetail";
import { ObjectList } from "./pages/ObjectList";
import { Sources } from "./pages/Sources";

export function AppRoutes() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/objets/:type" element={<ObjectList />} />
        <Route path="/objets/:type/:key" element={<ObjectDetail />} />
        <Route path="/graphe/:type/:key" element={<Graph />} />
        <Route path="/sources" element={<Sources />} />
        <Route
          path="*"
          element={
            <Notice>
              Cette page n'existe pas. <Link to="/">Retour à l'accueil</Link>
            </Notice>
          }
        />
      </Routes>
    </Layout>
  );
}
