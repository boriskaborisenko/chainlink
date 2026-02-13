import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { AppKitProvider, appKitConfig } from "./lib/appkit";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AppKitProvider {...appKitConfig}>
      <App />
    </AppKitProvider>
  </React.StrictMode>
);
