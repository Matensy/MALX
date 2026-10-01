import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import AnalysisLayout from "./pages/analysis/AnalysisLayout";
import BoardPage from "./pages/analysis/Board";
import EvidencePage from "./pages/analysis/Evidence";
import FindingsPage from "./pages/analysis/Findings";
import GraphPage from "./pages/analysis/Graph";
import IocsPage from "./pages/analysis/Iocs";
import MitrePage from "./pages/analysis/Mitre";
import Overview from "./pages/analysis/Overview";
import ReportPage from "./pages/analysis/Report";
import ReversePage from "./pages/analysis/Reverse";
import SecurityPage from "./pages/analysis/Security";
import StaticPage from "./pages/analysis/Static";
import TimelinePage from "./pages/analysis/Timeline";
import Dashboard from "./pages/Dashboard";
import IocCenter from "./pages/IocCenter";
import NewAnalysis from "./pages/NewAnalysis";
import SearchPage from "./pages/Search";
import SettingsPage from "./pages/Settings";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/analysis/new" element={<NewAnalysis />} />
          <Route path="/analysis/:id" element={<AnalysisLayout />}>
            <Route index element={<Overview />} />
            <Route path="static" element={<StaticPage />} />
            <Route path="reverse" element={<ReversePage />} />
            <Route path="security" element={<SecurityPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="evidence" element={<EvidencePage />} />
            <Route path="graph" element={<GraphPage />} />
            <Route path="timeline" element={<TimelinePage />} />
            <Route path="iocs" element={<IocsPage />} />
            <Route path="mitre" element={<MitrePage />} />
            <Route path="board" element={<BoardPage />} />
            <Route path="report" element={<ReportPage />} />
          </Route>
          <Route path="/iocs" element={<IocCenter />} />
          <Route path="/search" element={<SearchPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
