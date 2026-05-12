import { AppBar, Box, Button, Container, Toolbar, Typography } from "@mui/material";
import { Link, Route, Routes, useLocation } from "react-router-dom";
import { OverviewPage } from "./pages/OverviewPage";
import { TargetsPage } from "./pages/TargetsPage";
import { RunsPage } from "./pages/RunsPage";
import { RunDetailPage } from "./pages/RunDetailPage";
import { GraphPage } from "./pages/GraphPage";
import { PipelinePage } from "./pages/PipelinePage";
import { AgenticReconPage } from "./pages/AgenticReconPage";
import { BackendPage } from "./pages/BackendPage";

function NavButton({ to, label }: { to: string; label: string }) {
  const loc = useLocation();
  const active = loc.pathname === to || (to !== "/" && loc.pathname.startsWith(to));
  return (
    <Button
      component={Link}
      to={to}
      color={active ? "secondary" : "inherit"}
      variant={active ? "contained" : "text"}
      size="small"
      sx={{ mr: 1 }}
    >
      {label}
    </Button>
  );
}

export function App() {
  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "background.default" }}>
      <AppBar position="sticky">
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            Talakunchi Security Prototype
          </Typography>
          <NavButton to="/" label="Overview" />
          <NavButton to="/targets" label="Targets" />
          <NavButton to="/agents" label="Agentic Recon" />
          <NavButton to="/pipeline" label="Pipeline" />
          <NavButton to="/backend" label="Backend" />
          <NavButton to="/graph" label="Graph" />
        </Toolbar>
      </AppBar>

      <Container sx={{ py: 3 }}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/targets" element={<TargetsPage />} />
          <Route path="/runs" element={<RunsPage />} />
          <Route path="/runs/:id" element={<RunDetailPage />} />
          <Route path="/pipeline" element={<PipelinePage />} />
          <Route path="/agents" element={<AgenticReconPage />} />
          <Route path="/backend" element={<BackendPage />} />
          <Route path="/graph" element={<GraphPage />} />
        </Routes>
      </Container>
    </Box>
  );
}

